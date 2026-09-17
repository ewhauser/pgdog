use fnv::FnvHashSet;

use crate::frontend::router::parser::statement::{AdvisoryLocks as ParserAdvisoryLocks, LockScope};

/// Tracks advisory locks held by the current client across requests.
#[derive(Default, Debug)]
pub(crate) struct AdvisoryLocks {
    locks: FnvHashSet<i64>,
    observed: bool,
}

impl AdvisoryLocks {
    pub(crate) fn merge(&mut self, locks: &ParserAdvisoryLocks) {
        for lock in locks.iter() {
            if lock.unlock {
                if let Some(id) = lock.id {
                    self.locks.remove(&id);
                } else {
                    // pg_advisory_unlock_all() clears every advisory lock.
                    self.locks.clear();
                }
            } else if let Some(id) = lock.id
                && lock.scope == LockScope::Session
            {
                self.locks.insert(id);
            }
        }
    }

    pub(crate) fn locked(&self) -> bool {
        self.observed || !self.locks.is_empty()
    }

    /// Reconcile parser bookkeeping with the locks PostgreSQL actually holds.
    pub(crate) fn reconcile(&mut self, held: bool) {
        self.observed = held;
        if !held {
            self.locks.clear();
        }
    }

    #[cfg(test)]
    pub(crate) fn contains(&self, id: i64) -> bool {
        self.locks.contains(&id)
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.locks.len()
    }
}
