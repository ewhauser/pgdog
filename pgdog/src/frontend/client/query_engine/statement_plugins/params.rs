//! Bind parameters (`$n`) of a statement, found by scanning its text.
//!
//! The AST walker doesn't support every statement type, so this follows
//! Postgres' lexer instead: `$n` counts unless it's inside a string, a quoted
//! identifier, a comment or a dollar-quoted string.

/// Highest bind parameter number in a statement, 0 if it has none. `None` if
/// the statement ends inside a string, identifier or comment.
pub(super) fn max_parameter(sql: &str) -> Option<u32> {
    let bytes = sql.as_bytes();
    let mut max = 0;
    let mut i = 0;

    while i < bytes.len() {
        match bytes[i] {
            // String, with '' escapes. E'' strings also escape with backslashes.
            b'\'' => {
                let escapes = i > 0
                    && matches!(bytes[i - 1], b'e' | b'E')
                    && (i < 2 || !is_ident(bytes[i - 2]));
                i = end_of_quoted(bytes, i + 1, b'\'', escapes)?;
            }
            b'"' => i = end_of_quoted(bytes, i + 1, b'"', false)?,
            b'-' if bytes.get(i + 1) == Some(&b'-') => {
                i = bytes[i..]
                    .iter()
                    .position(|byte| *byte == b'\n')
                    .map_or(bytes.len(), |end| i + end + 1);
            }
            // Block comments nest.
            b'/' if bytes.get(i + 1) == Some(&b'*') => {
                let mut depth = 1;
                i += 2;
                while depth > 0 {
                    match (bytes.get(i)?, bytes.get(i + 1)) {
                        (b'/', Some(b'*')) => {
                            depth += 1;
                            i += 2;
                        }
                        (b'*', Some(b'/')) => {
                            depth -= 1;
                            i += 2;
                        }
                        _ => i += 1,
                    }
                }
            }
            b'$' if i > 0 && is_ident(bytes[i - 1]) => i += 1,
            b'$' => {
                let digits = bytes[i + 1..]
                    .iter()
                    .take_while(|byte| byte.is_ascii_digit())
                    .count();
                if digits > 0 {
                    max = max.max(sql[i + 1..i + 1 + digits].parse().ok()?);
                    i += 1 + digits;
                } else {
                    // Dollar quote: $tag$ ... $tag$.
                    let tag_len = bytes[i + 1..]
                        .iter()
                        .take_while(|byte| is_ident(**byte) && !byte.is_ascii_digit())
                        .count();
                    if bytes.get(i + 1 + tag_len) == Some(&b'$') {
                        let tag = &sql[i..i + tag_len + 2];
                        let body = i + tag.len();
                        i = body + sql[body..].find(tag)? + tag.len();
                    } else {
                        i += 1;
                    }
                }
            }
            _ => i += 1,
        }
    }

    Some(max)
}

fn is_ident(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_' || byte >= 0x80
}

/// Position after the closing quote. A doubled quote is an escaped one.
fn end_of_quoted(bytes: &[u8], mut i: usize, quote: u8, backslashes: bool) -> Option<usize> {
    loop {
        match *bytes.get(i)? {
            b'\\' if backslashes => i += 2,
            byte if byte == quote => {
                if bytes.get(i + 1) == Some(&quote) {
                    i += 2;
                } else {
                    return Some(i + 1);
                }
            }
            _ => i += 1,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_max_parameter() {
        assert_eq!(max_parameter("SELECT 1"), Some(0));
        assert_eq!(max_parameter("SELECT $1, $12, $3"), Some(12));
        assert_eq!(
            max_parameter("COPY (SELECT * FROM t WHERE id = $2) TO STDOUT"),
            Some(2)
        );
        // Not parameters.
        assert_eq!(max_parameter("SELECT '$1', \"$2\" FROM t"), Some(0));
        assert_eq!(max_parameter("SELECT 'it''s $1'"), Some(0));
        assert_eq!(max_parameter("SELECT E'\\' $1'"), Some(0));
        assert_eq!(max_parameter("SELECT 1 -- $1\n, $2"), Some(2));
        assert_eq!(max_parameter("SELECT /* /* $1 */ $2 */ $3"), Some(3));
        assert_eq!(max_parameter("SELECT $$ $1 $$, $fn$ $2 $fn$, $3"), Some(3));
        assert_eq!(max_parameter("SELECT a$1 FROM t"), Some(0));
        // Unterminated.
        assert_eq!(max_parameter("SELECT 'open"), None);
        assert_eq!(max_parameter("SELECT /* open"), None);
        assert_eq!(max_parameter("SELECT $$ open"), None);
    }
}
