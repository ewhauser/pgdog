//! Plugin capabilities.
//!
//! Plugins declare which hooks PgDog should call by returning a set of
//! capabilities from [`crate::Plugin::capabilities`]. PgDog skips hooks
//! a plugin didn't ask for, so a routing-only plugin pays nothing for the
//! statement and result hooks.
//!
//! ### Example
//!
//! ```
//! use pgdog_plugin::Capabilities;
//!
//! let caps = Capabilities::STATEMENT | Capabilities::MASK;
//! assert!(caps.contains(Capabilities::STATEMENT));
//! assert!(!caps.contains(Capabilities::ROUTE));
//! ```
use std::ops::{BitOr, BitOrAssign};

/// Set of hooks a plugin implements.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Capabilities(u64);

impl Capabilities {
    /// No hooks.
    pub const NONE: Self = Self(0);
    /// [`crate::Plugin::route`] is called for every routed statement.
    pub const ROUTE: Self = Self(1 << 0);
    /// [`crate::Plugin::statement`] and [`crate::Plugin::function_call`] are
    /// called before PgDog parses a statement, and can rewrite or deny it.
    /// Only one loaded plugin can have this capability.
    pub const STATEMENT: Self = Self(1 << 1);
    /// [`crate::Plugin::mask_rows`] is called for result columns the plugin's
    /// statement verdicts asked to mask. Requires [`Self::STATEMENT`].
    pub const MASK: Self = Self(1 << 2);
    /// [`crate::Plugin::redact_error`] is called for every error and notice
    /// Postgres sends to a client.
    pub const ERRORS: Self = Self(1 << 3);
    /// [`crate::Plugin::catalog`] receives the database catalog. Forces PgDog
    /// to load the schema even if `load_schema` would otherwise skip it.
    pub const CATALOG: Self = Self(1 << 4);

    /// Create capabilities from raw bits. Unknown bits are kept, so a newer
    /// plugin can't be misread by an older host.
    pub const fn from_bits(bits: u64) -> Self {
        Self(bits)
    }

    /// Raw bits.
    pub const fn bits(self) -> u64 {
        self.0
    }

    /// All capabilities in `other` are present in `self`.
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

impl BitOr for Capabilities {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl BitOrAssign for Capabilities {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_contains() {
        let caps = Capabilities::ROUTE | Capabilities::CATALOG;
        assert!(caps.contains(Capabilities::ROUTE));
        assert!(caps.contains(Capabilities::ROUTE | Capabilities::CATALOG));
        assert!(!caps.contains(Capabilities::STATEMENT));
        assert!(caps.contains(Capabilities::NONE));
    }
}
