//! Wrapper around Rust's [`str`], a UTF-8 encoded slice.
//!
//! This is used to pass strings back and forth between the plugin and
//! PgDog, without allocating memory as required by [`std::ffi::CString`].
//!
//! ### Example
//!
//! ```
//! use pgdog_plugin::PdStr;
//! use std::ops::Deref;
//!
//! let string = PdStr::from("hello world");
//! assert_eq!(string.deref(), "hello world");
//!
//! let string = string.to_string(); // Owned version.
//! ```
//!
use std::{ops::Deref, ptr, slice, str};

#[repr(C)]
/// A wrapper around a rust `&str`
#[derive(Clone, Copy)]
pub struct PdStr<'a> {
    data: Option<&'a u8>,
    len: usize,
}

impl<'a> From<&'a str> for PdStr<'a> {
    fn from(value: &'a str) -> Self {
        PdStr {
            data: value.as_bytes().first(),
            len: value.len(),
        }
    }
}

impl<'a> PdStr<'a> {
    /// The string, for as long as the data it borrows.
    pub fn as_str(&self) -> &'a str {
        // SAFETY: The only way to construct this is from a valid string
        // that outlives 'a.
        unsafe {
            str::from_utf8_unchecked(slice::from_raw_parts(
                self.data.map(ptr::from_ref).unwrap_or(ptr::dangling()),
                self.len,
            ))
        }
    }
}

impl Deref for PdStr<'_> {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

impl std::fmt::Debug for PdStr<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(&**self, f)
    }
}

impl PartialEq for PdStr<'_> {
    fn eq(&self, other: &Self) -> bool {
        **self == **other
    }
}

impl Default for PdStr<'_> {
    fn default() -> Self {
        Self::from("")
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_pd_str() {
        let s = "one_two_three";
        let pd = PdStr::from(s);
        assert_eq!(pd.deref(), "one_two_three");

        let s = String::from("one_two");
        let pd = PdStr::from(&*s);
        assert_eq!(pd.deref(), "one_two");
        assert_eq!(&*pd, "one_two");
    }
}
