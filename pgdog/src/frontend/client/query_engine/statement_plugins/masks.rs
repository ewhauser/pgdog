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
        // Columns of every row, `width` per row.
        let mut fields = Vec::new();
        let width = parse_row(&payloads[0], &mut fields).ok_or("malformed DataRow")?;
        for payload in &payloads[1..] {
            if parse_row(payload, &mut fields).ok_or("malformed DataRow")? != width {
                return Err("rows of a result set have different widths".into());
            }
        }

        // Column position -> index of its mask.
        let mut masked = vec![None; width];
        for (index, mask) in masks.iter().enumerate() {
            let slot = masked
                .get_mut(mask.column as usize)
                .ok_or_else(|| format!("masked column {} doesn't exist", mask.column))?;
            *slot = Some(index);
        }
        // Masked columns in row order, with the index of their mask.
        let targets: Vec<(usize, usize)> = masked
            .iter()
            .enumerate()
            .filter_map(|(column, index)| index.map(|index| (column, index)))
            .collect();

        let values: Vec<Vec<Value<'_>>> = masks
            .iter()
            .map(|mask| {
                fields
                    .chunks_exact(width)
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
        let count = rows.len();
        let masked_value = |row: usize, index: usize| output.get(index * count + row);

        // All rows go in one buffer, sized for the masked values: they are
        // often longer than the originals.
        let mut size = 0;
        for (row, (fields, payload)) in fields.chunks_exact(width).zip(&payloads).enumerate() {
            size += payload.len();
            for &(column, index) in &targets {
                size += masked_value(row, index).map_or(0, <[u8]>::len);
                size -= fields[column].1.max(0) as usize;
            }
        }
        let mut buf = BytesMut::with_capacity(size);

        for (row, (fields, payload)) in fields.chunks_exact(width).zip(&payloads).enumerate() {
            // Columns between masked ones are copied as they are, lengths included.
            let mut copied = 0;
            for &(column, index) in &targets {
                let (start, len) = fields[column];
                buf.put_slice(&payload[copied..start - 4]);
                match masked_value(row, index) {
                    Some(value) => {
                        buf.put_i32(value.len() as i32);
                        buf.put_slice(value);
                    }
                    None => buf.put_i32(-1),
                }
                copied = start + len.max(0) as usize;
            }
            // Up to the end of the last column: there is at least one.
            let (start, len) = fields[width - 1];
            buf.put_slice(&payload[copied..start + len.max(0) as usize]);
            let len = buf.len() as i32 - 1;
            buf[1..5].copy_from_slice(&len.to_be_bytes());
            rows[row].replace_payload(buf.split().freeze());
        }

        Ok(())
    }
}

/// Append the start and length (-1 for NULL) of each column of a `DataRow`
/// to `fields`. Returns the number of columns.
fn parse_row(payload: &[u8], fields: &mut Vec<(usize, i32)>) -> Option<usize> {
    let count = i16::from_be_bytes(payload.get(5..7)?.try_into().ok()?).max(0) as usize;
    fields.reserve(count);
    let mut offset = 7;

    for _ in 0..count {
        let len = i32::from_be_bytes(payload.get(offset..offset + 4)?.try_into().ok()?);
        offset += 4;
        fields.push((offset, len));
        if len > 0 {
            offset += len as usize;
        }
    }

    (offset <= payload.len()).then_some(count)
}

/// A column's value. `None` is NULL.
fn field(payload: &[u8], (start, len): (usize, i32)) -> Option<&[u8]> {
    (len >= 0).then(|| &payload[start..start + len as usize])
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::net::{DataRow, Protocol, ToBytes};
    use crate::plugin::test::{DIGEST, DIGEST_VALUE, UPPERCASE, test_plugin};

    #[test]
    fn test_parse_row() {
        let mut row = DataRow::new();
        row.add("abc").add(None::<String>).add("");
        let payload = row.to_bytes();
        let mut fields = vec![(0, 0)];
        assert_eq!(parse_row(&payload, &mut fields), Some(3));
        let fields = &fields[1..];
        assert_eq!(field(&payload, fields[0]), Some(b"abc".as_slice()));
        assert_eq!(field(&payload, fields[1]), None);
        assert_eq!(field(&payload, fields[2]), Some(b"".as_slice()));

        // Truncated.
        assert!(parse_row(&payload[..payload.len() - 2], &mut Vec::new()).is_none());
    }

    fn masking(columns: Vec<ColumnMask>) -> Masking {
        Masking {
            plan: Arc::new(Plan {
                plugin: test_plugin(),
                columns,
            }),
            result: 0,
            formats: None,
        }
    }

    fn data_row(values: &[Option<&str>]) -> Message {
        let mut row = DataRow::new();
        for value in values {
            row.add(value.map(str::to_owned));
        }
        row.message()
    }

    #[test]
    fn test_mask_rows() {
        let digest = std::str::from_utf8(&DIGEST_VALUE).unwrap();
        let masking = masking(vec![
            ColumnMask::new(0, DIGEST, 25),
            ColumnMask::new(2, UPPERCASE, 25),
        ]);
        let mut rows = vec![
            data_row(&[Some("123-45-6789"), Some("kept"), Some("abc")]),
            data_row(&[None, None, Some("")]),
            data_row(&[Some(""), Some("x"), None]),
        ];

        masking.mask(&mut rows).unwrap();

        let expected = [
            data_row(&[Some(digest), Some("kept"), Some("ABC")]),
            data_row(&[None, None, Some("")]),
            data_row(&[Some(digest), Some("x"), None]),
        ];
        for (row, expected) in rows.iter().zip(&expected) {
            assert_eq!(row.payload(), expected.payload());
        }
    }

    #[test]
    fn test_mask_rows_errors() {
        let masking = masking(vec![ColumnMask::new(0, DIGEST, 25)]);

        let mut rows = vec![data_row(&[Some("a")]), data_row(&[Some("a"), Some("b")])];
        assert!(masking.mask(&mut rows).is_err());

        let mut rows = vec![Message::new(Bytes::from_static(b"D\0\0\0\x06\0\x01"))];
        assert!(masking.mask(&mut rows).is_err());

        let masking = self::masking(vec![ColumnMask::new(3, DIGEST, 25)]);
        let mut rows = vec![data_row(&[Some("a")])];
        assert!(masking.mask(&mut rows).is_err());
    }

    /// `cargo test --release -p pgdog bench_mask_rows -- --ignored --nocapture`
    #[test]
    #[ignore]
    #[allow(clippy::print_stdout)]
    fn bench_mask_rows() {
        use std::time::Instant;

        const ITERATIONS: usize = 20_000;
        let masking = masking(vec![ColumnMask::new(1, DIGEST, 25)]);
        let rows: Vec<Message> = (0..MAX_BATCH_ROWS)
            .map(|i| {
                let id = i.to_string();
                data_row(&[
                    Some(&id),
                    Some("123-45-6789"),
                    Some("Jane Doe"),
                    Some("jane@example.com"),
                    None,
                ])
            })
            .collect();

        let start = Instant::now();
        for _ in 0..ITERATIONS {
            let mut batch = rows.clone();
            masking.mask(&mut batch).unwrap();
            std::hint::black_box(&batch);
        }
        let elapsed = start.elapsed();
        println!(
            "Masking::mask: {:.1} ns/row ({} rows x {ITERATIONS})",
            elapsed.as_nanos() as f64 / (ITERATIONS * rows.len()) as f64,
            rows.len(),
        );
    }
}
