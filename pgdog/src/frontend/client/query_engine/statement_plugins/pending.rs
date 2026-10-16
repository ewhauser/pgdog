//! Attribute server messages to the client messages they respond to, so
//! `DataRow`s are masked with the plan of the statement that produced them.
use std::collections::VecDeque;
use std::sync::Arc;

use tracing::debug;

use super::masks::{Masking, Plan, PortalPlan};

/// A client message still waiting for its responses, with the mask plan of
/// what it runs, if any.
#[derive(Debug, Clone)]
pub(super) enum Pending {
    /// Simple query or fast-path call: everything until `ReadyForQuery`.
    Query {
        plan: Option<Arc<Plan>>,
        /// Result set being returned, counting from 0.
        result: u16,
    },
    Parse,
    Bind,
    DescribeStatement(Option<Arc<Plan>>),
    DescribePortal(Option<PortalPlan>),
    Execute(Option<PortalPlan>),
    Close,
    Sync,
}

/// What a server message does to the head of the pending queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Response {
    /// The message is part of the response; more is coming.
    Partial,
    /// The message completes the response.
    Complete,
    /// The message is an error: the response is complete, and so are the
    /// rest of the extended protocol messages until `Sync`.
    Error,
    /// The message isn't a response to it: the response came from PgDog.
    Unrelated,
}

impl Pending {
    fn response(&self, code: char, client_visible: bool) -> Response {
        use Response::*;

        match (self, code) {
            // Internally split queries send ReadyForQuery for each part;
            // only the one the client sees ends the query.
            (Self::Query { .. }, 'Z') if client_visible => Complete,
            (Self::Query { .. }, _) => Partial,
            (Self::Parse, '1') => Complete,
            (Self::Bind, '2') => Complete,
            (Self::DescribeStatement(_), 't') => Partial,
            (Self::DescribeStatement(_), 'T' | 'n') => Complete,
            (Self::DescribePortal(_), 'T' | 'n') => Complete,
            (Self::Execute(_), 'C' | 's' | 'I') => Complete,
            (Self::Execute(_), '1' | '2' | '3' | 't' | 'Z') => Unrelated,
            (Self::Execute(_), _) => Partial,
            (Self::Close, '3') => Complete,
            (Self::Sync, 'Z') => Complete,
            // Errors belong to the message that failed. Postgres then skips the
            // rest of the extended protocol messages until Sync.
            (Self::Sync, 'E') => Partial,
            (_, 'E') => Error,
            // Notices and parameter changes belong to whatever is running.
            (_, 'N' | 'S' | 'A') => Partial,
            _ => Unrelated,
        }
    }

    /// The plan for the server message, before `code` is applied.
    fn masking(&self) -> Option<Masking> {
        match self {
            Self::Query {
                plan: Some(plan),
                result,
            } => Some(Masking {
                plan: plan.clone(),
                result: *result,
                formats: None,
            }),
            Self::DescribeStatement(Some(plan)) => Some(Masking {
                plan: plan.clone(),
                result: 0,
                formats: None,
            }),
            Self::DescribePortal(Some(portal)) | Self::Execute(Some(portal)) => Some(Masking {
                plan: portal.plan.clone(),
                result: 0,
                formats: Some(portal.formats.clone()),
            }),
            _ => None,
        }
    }
}

/// Client messages waiting for responses, in order.
#[derive(Debug, Default)]
pub(super) struct PendingQueue {
    queue: VecDeque<Pending>,
}

impl PendingQueue {
    pub(super) fn extend(&mut self, pending: impl IntoIterator<Item = Pending>) {
        self.queue.extend(pending);
    }

    pub(super) fn clear(&mut self) {
        self.queue.clear();
    }

    /// The mask plan of what a server message responds to. Consumes the pending
    /// client message the server message completes.
    pub(super) fn masking(&mut self, code: char, client_visible: bool) -> Option<Masking> {
        loop {
            let head = self.queue.front_mut()?;
            match head.response(code, client_visible) {
                Response::Partial => {
                    let masking = head.masking();
                    // The next result set of a multi-statement query.
                    if let Pending::Query { result, .. } = head
                        && matches!(code, 'C' | 'I')
                    {
                        *result = result.saturating_add(1);
                    }
                    return masking;
                }
                Response::Complete => return self.queue.pop_front()?.masking(),
                Response::Error => {
                    let head = self.queue.pop_front()?;
                    while self.queue.front().is_some_and(|pending| {
                        !matches!(pending, Pending::Sync | Pending::Query { .. })
                    }) {
                        self.queue.pop_front();
                    }
                    return head.masking();
                }
                Response::Unrelated => {
                    // The response to this message was produced by PgDog itself, not
                    // the server, so it never reaches us. Move on to the next one.
                    debug!(
                        "statement plugins: no response for {:?} before '{code}'",
                        self.queue.front()
                    );
                    self.queue.pop_front();
                }
            }
        }
    }
}
