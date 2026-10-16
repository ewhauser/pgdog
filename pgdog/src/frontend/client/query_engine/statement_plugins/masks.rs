//! Column masks: pass the masked columns of `DataRow`s through the plugin,
//! a batch of rows at a time.
use std::sync::Arc;

use bytes::{BufMut, Bytes, BytesMut};
use pgdog_plugin::{ColumnMask, MaskBatch, MaskColumn, Value};

use crate::net::{Format, FromBytes, Message, RowDescription};
use crate::plugin::LoadedPlugin;

/// Most rows masked in one call.
pub(super) const MAX_BATCH_ROWS: usize = 256;
/// Most bytes of rows masked in one call.
pub(super) const MAX_BATCH_BYTES: usize = 1024 * 1024;

/// Columns to mask, from a statement's verdict.
#[derive(Debug)]
pub(super) struct Plan {
    pub(super) plugin: &'static LoadedPlugin,
    pub(super) columns: Vec<ColumnMask>,
}

/// A portal's mask plan, with the result formats the client asked for in its `Bind`.
#[derive(Debug, Clone)]
pub(super) struct PortalPlan {
    pub(super) plan: Arc<Plan>,
    pub(super) formats: Arc<[Format]>,
}

/// The plan applying to a server message, and which result set it belongs to.
#[derive(Debug, Clone)]
pub(crate) struct Masking {
    pub(super) plan: Arc<Plan>,
    pub(super) result: u16,
    /// Result formats from the portal's `Bind`; `None` for simple queries,
    /// where every column is text.
    pub(super) formats: Option<Arc<[Format]>>,
}

impl Masking {
    /// Masked columns of the current result set.
    fn columns(&self) -> impl Iterator<Item = &ColumnMask> {
        let result = self.result;
        self.plan
            .columns
            .iter()
            .filter(move |column| column.result == result)
    }

    /// Masking this result set may block.
    pub(super) fn blocking(&self) -> bool {
        self.columns().any(|column| column.blocking)
    }

    /// Format of a result column. Follows the protocol: no codes means text, one
    /// code applies to all columns, otherwise there is one per column.
    fn format(&self, column: u16) -> Format {
        match self.formats.as_deref() {
            None | Some([]) => Format::Text,
            Some([format]) => *format,
            Some(formats) => formats
                .get(column as usize)
                .copied()
                .unwrap_or(Format::Text),
        }
    }

    /// Check that masked columns exist and have the types the plugin declared.
    /// Returns why not.
    pub(super) fn check(&self, message: &Message) -> Result<(), String> {
        let description = RowDescription::from_bytes(message.payload())
            .map_err(|err| format!("invalid RowDescription: {err}"))?;

        for mask in self.columns() {
            let field = description
                .fields
                .get(mask.column as usize)
                .ok_or_else(|| format!("masked column {} doesn't exist", mask.column))?;
            if field.type_oid as u32 != mask.type_oid {
                return Err(format!(
                    "masked column \"{}\" has type OID {}, the plugin expected {}",
                    field.name, field.type_oid, mask.type_oid
                ));
            }
        }

        Ok(())
    }

    /// Mask a batch of `DataRow`s in place.
    pub(super) fn mask(&self, rows: &mut [Message]) -> Result<(), String> {
        let masks: Vec<&ColumnMask> = self.columns().collect();
        if masks.is_empty() || rows.is_empty() {
            return Ok(());
        }

        let payloads: Vec<Bytes> = rows.iter().map(|row| row.payload()).collect();
        let parsed = payloads
            .iter()
            .map(|payload| parse_row(payload))
            .collect::<Option<Vec<_>>>()
            .ok_or("malformed DataRow")?;
        let width = parsed[0].len();
        if parsed.iter().any(|fields| fields.len() != width) {
            return Err("rows of a result set have different widths".into());
        }

        // Column position -> index of its mask.
        let mut masked = vec![None; width];
        for (index, mask) in masks.iter().enumerate() {
            let slot = masked
                .get_mut(mask.column as usize)
                .ok_or_else(|| format!("masked column {} doesn't exist", mask.column))?;
            *slot = Some(index);
        }

        let values: Vec<Vec<Value<'_>>> = masks
            .iter()
            .map(|mask| {
                parsed
                    .iter()
                    .zip(&payloads)
                    .map(|(fields, payload)| {
                        Value::new(field(payload, fields[mask.column as usize]))
                    })
                    .collect()
            })
            .collect();
        let columns: Vec<MaskColumn<'_>> = masks
            .iter()
            .zip(&values)
            .map(|(mask, values)| MaskColumn::new(mask, self.format(mask.column), values))
            .collect();
        let batch = MaskBatch::new(rows.len() as u32, &columns);
        let output = self
            .plan
            .plugin
            .vtable()
            .mask_rows(&batch)
            .map_err(|err| err.to_string())?;

        for (row, (fields, payload)) in parsed.iter().zip(&payloads).enumerate() {
            let mut buf = BytesMut::with_capacity(payload.len());
            buf.put_u8(b'D');
            buf.put_i32(0);
            buf.put_i16(width as i16);
            for (column, &(start, len)) in fields.iter().enumerate() {
                let value = match masked[column] {
                    Some(index) => output.get(index * rows.len() + row),
                    None => field(payload, (start, len)),
                };
                match value {
                    Some(value) => {
                        buf.put_i32(value.len() as i32);
                        buf.put_slice(value);
                    }
                    None => buf.put_i32(-1),
                }
            }
            let len = buf.len() as i32 - 1;
            buf[1..5].copy_from_slice(&len.to_be_bytes());
            rows[row].replace_payload(buf.freeze());
        }

        Ok(())
    }
}

/// Start and length (-1 for NULL) of each column of a `DataRow`.
fn parse_row(payload: &[u8]) -> Option<Vec<(usize, i32)>> {
    let count = i16::from_be_bytes(payload.get(5..7)?.try_into().ok()?);
    let mut fields = Vec::with_capacity(count.max(0) as usize);
    let mut offset = 7;

    for _ in 0..count {
        let len = i32::from_be_bytes(payload.get(offset..offset + 4)?.try_into().ok()?);
        offset += 4;
        fields.push((offset, len));
        if len > 0 {
            offset += len as usize;
        }
    }

    (offset <= payload.len()).then_some(fields)
}

/// A column's value. `None` is NULL.
fn field(payload: &[u8], (start, len): (usize, i32)) -> Option<&[u8]> {
    (len >= 0).then(|| &payload[start..start + len as usize])
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::net::{DataRow, ToBytes};

    #[test]
    fn test_parse_row() {
        let mut row = DataRow::new();
        row.add("abc").add(None::<String>).add("");
        let payload = row.to_bytes();
        let fields = parse_row(&payload).unwrap();
        assert_eq!(fields.len(), 3);
        assert_eq!(field(&payload, fields[0]), Some(b"abc".as_slice()));
        assert_eq!(field(&payload, fields[1]), None);
        assert_eq!(field(&payload, fields[2]), Some(b"".as_slice()));

        // Truncated.
        assert!(parse_row(&payload[..payload.len() - 2]).is_none());
    }
}
