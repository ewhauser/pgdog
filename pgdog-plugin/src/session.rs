//! The client session hooks run for.
use crate::PdStr;

/// Who is running a statement, and the session settings that can change
/// what it means.
///
/// `user`, `database` and `tls_identity` are authenticated and fixed for the
/// session. Everything in [`ClientInfo`] is supplied by the client.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct Session<'a> {
    /// PgDog user the client authenticated as.
    pub user: PdStr<'a>,
    /// PgDog database the client connected to.
    pub database: PdStr<'a>,
    /// Identity from the client's verified TLS certificate (SAN DNS name, or
    /// subject CN), empty if the client didn't present one.
    pub tls_identity: PdStr<'a>,
    /// Session `search_path`, empty if the client didn't set one.
    pub search_path: PdStr<'a>,
    /// Details the client supplied about itself.
    pub client: ClientInfo<'a>,
}

impl Session<'_> {
    /// Identity from the client's verified TLS certificate, if any.
    pub fn tls_identity(&self) -> Option<&str> {
        Some(&*self.tls_identity).filter(|identity| !identity.is_empty())
    }
}

/// Details the client supplied about itself.
///
/// **Not authenticated.** Use them for logging or tagging, never for
/// access decisions.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct ClientInfo<'a> {
    /// `application_name`.
    pub application_name: PdStr<'a>,
    /// Client IP address, empty if unknown.
    pub addr: PdStr<'a>,
}
