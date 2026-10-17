//! Error redaction: pass the errors and notices Postgres sends through plugins.
use std::borrow::Cow;

use bytes::{BufMut, BytesMut};
use pgdog_plugin::{
    Capabilities, ErrorField, ErrorFields, Session,
    redact::field::{MESSAGE, SEVERITY, SEVERITY_NONLOCALIZED, SQLSTATE},
};
use tracing::error;

use crate::net::{Message, Protocol};
use crate::plugin::with_capability;

/// Replaces the message of an error a plugin failed to redact.
const REDACTION_FAILED: &str = "error details removed: plugin failed to redact them";

/// Fields of an `ErrorResponse` or `NoticeResponse`, in order.
fn parse(payload: &[u8]) -> Option<Vec<(u8, Cow<'_, str>)>> {
    let mut fields = vec![];
    let mut rest = payload.get(5..)?;

    loop {
        match rest.split_first()? {
            (0, _) => return Some(fields),
            (&code, tail) => {
                let end = tail.iter().position(|byte| *byte == 0)?;
                fields.push((code, String::from_utf8_lossy(&tail[..end])));
                rest = &tail[end + 1..];
            }
        }
    }
}

/// Pass an error or notice through every plugin that redacts errors, in
/// config order. Each plugin sees the fields the previous one returned.
pub(super) fn redact(session: &Session<'_>, message: &mut Message) {
    let payload = message.payload();
    let code = message.code();
    let original = match parse(&payload) {
        Some(fields) => fields,
        None => {
            error!("malformed '{code}' message from server, redacting it");
            vec![
                (SEVERITY, Cow::Borrowed("ERROR")),
                (SQLSTATE, "XX000".into()),
            ]
        }
    };

    let mut current: Option<Vec<(u8, String)>> = None;
    for plugin in with_capability(Capabilities::ERRORS) {
        let fields: Vec<ErrorField<'_>> = match &current {
            Some(fields) => fields
                .iter()
                .map(|(code, value)| ErrorField::new(*code, value.as_str().into()))
                .collect(),
            None => original
                .iter()
                .map(|(code, value)| ErrorField::new(*code, value.as_ref().into()))
                .collect(),
        };
        let error = ErrorFields::new(code == 'N', &fields);

        match plugin.vtable().redact_error(session, &error) {
            Ok(None) => (),
            Ok(Some(fields)) => current = Some(fields),
            Err(err) => {
                // Fail closed: keep only what clients need to handle the error.
                error!(
                    "plugin \"{}\" failed to redact an error: {err}",
                    plugin.name()
                );
                current = Some(vec![(MESSAGE, REDACTION_FAILED.into())]);
            }
        }
    }

    if let Some(redacted) = current {
        message.replace_payload(encode(code, &original, &redacted).freeze());
    }
}

/// Replaces the message of errors from statements whose errors the plugin
/// asked to redact.
const STATEMENT_REDACTED: &str =
    "error message removed: the statement reads values this user can't see";

/// Fields kept when a statement's errors are redacted: they describe where
/// the error is, not the data. Severity and SQLSTATE are always kept.
const LOCATION_FIELDS: &[u8] = b"PFLRstcdn";

/// Replace the message of an error or notice from a statement whose errors
/// the plugin asked to redact, e.g. one that compares values its user can't
/// see, which an error such as `invalid input syntax` would quote. Keeps the
/// severity, SQLSTATE, position and the names of the objects involved.
pub(super) fn redact_statement(message: &mut Message) {
    let payload = message.payload();
    let code = message.code();
    let original = parse(&payload).unwrap_or_default();
    let mut redacted: Vec<(u8, String)> = vec![(MESSAGE, STATEMENT_REDACTED.into())];
    redacted.extend(
        original
            .iter()
            .filter(|(field, _)| LOCATION_FIELDS.contains(field))
            .map(|(field, value)| (*field, value.to_string())),
    );
    message.replace_payload(encode(code, &original, &redacted).freeze());
}

/// Build the redacted message: the original severity and SQLSTATE, then the
/// plugin's fields.
fn encode(code: char, original: &[(u8, Cow<'_, str>)], redacted: &[(u8, String)]) -> BytesMut {
    let kept = [SEVERITY, SEVERITY_NONLOCALIZED, SQLSTATE];
    let mut buf = BytesMut::new();
    buf.put_u8(code as u8);
    buf.put_i32(0);

    let mut put = |field: u8, value: &str| {
        buf.put_u8(field);
        buf.put_slice(value.as_bytes());
        buf.put_u8(0);
    };
    for (field, value) in original.iter().filter(|(field, _)| kept.contains(field)) {
        put(*field, value);
    }
    for (field, value) in redacted.iter().filter(|(field, _)| !kept.contains(field)) {
        put(*field, value);
    }
    // Clients expect a message.
    if !redacted.iter().any(|(field, _)| *field == MESSAGE) {
        put(MESSAGE, "");
    }

    buf.put_u8(0);
    let len = buf.len() as i32 - 1;
    buf[1..5].copy_from_slice(&len.to_be_bytes());
    buf
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::net::{ErrorResponse, FromBytes, ToBytes};
    use pgdog_plugin::redact::field::{DETAIL, POSITION};

    #[test]
    fn test_parse_and_encode() {
        let error = ErrorResponse {
            code: "23505".into(),
            message: "duplicate key".into(),
            detail: Some("Key (ssn)=(123) already exists.".into()),
            ..Default::default()
        };
        let payload = error.to_bytes();
        let fields = parse(&payload).unwrap();
        assert!(fields.contains(&(DETAIL, "Key (ssn)=(123) already exists.".into())));

        // Plugins can't change the severity or SQLSTATE, and can't drop the message.
        let redacted = encode(
            'E',
            &fields,
            &[(SQLSTATE, "00000".into()), (SEVERITY, "LOG".into())],
        );
        let message = Message::new(redacted.freeze());
        let error = ErrorResponse::from_bytes(message.payload()).unwrap();
        assert_eq!(error.code, "23505");
        assert_eq!(error.severity, "ERROR");
        assert_eq!(error.message, "");
        assert_eq!(error.detail, None);
    }

    #[test]
    fn test_redact_statement() {
        let error = ErrorResponse {
            code: "22P02".into(),
            message: "invalid input syntax for type integer: \"123-45-6789\"".into(),
            detail: Some("123-45-6789".into()),
            ..Default::default()
        };
        let mut payload = error.to_bytes().to_vec();
        // Add a position field before the terminator.
        payload.pop();
        payload.extend(b"P42\0\0");
        let len = payload.len() as i32 - 1;
        payload[1..5].copy_from_slice(&len.to_be_bytes());
        let mut message = Message::new(payload.into());

        redact_statement(&mut message);
        let payload = message.payload();
        let fields = parse(&payload).unwrap();
        let text = format!("{fields:?}");
        assert!(!text.contains("123-45-6789"), "{text}");
        assert!(fields.contains(&(SQLSTATE, "22P02".into())));
        assert!(fields.contains(&(POSITION, "42".into())));
        assert!(fields.contains(&(MESSAGE, STATEMENT_REDACTED.into())));
        assert!(!fields.iter().any(|(field, _)| *field == DETAIL));
    }
}
