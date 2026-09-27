//! The connections one worker holds, so that stopping its server reaches
//! every one of them. One per [`Server::run`](super::Server::run), and so per
//! worker: nothing here crosses a thread.

use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::task::{Poll, Waker};
use std::time::{Duration, SystemTime};

use rustc_hash::FxHashMap;

use crate::shared::connection::SharedConnection;

#[derive(Default)]
pub(crate) struct Shutdown {
    /// Set once: what the connections still open must be done by.
    until: Cell<Option<SystemTime>>,
    /// `None` until the connection exists: a TLS handshake is counted from
    /// its accept, and has no loop to wake before it ends.
    members: RefCell<FxHashMap<u64, Option<Rc<SharedConnection>>>>,
    next_id: Cell<u64>,
    /// `Server::run`, waiting on the last member to leave.
    emptied: RefCell<Option<Waker>>,
}

impl Shutdown {
    pub(crate) fn join(self: &Rc<Self>) -> Registration {
        let id = self.next_id.get();
        self.next_id.set(id + 1);
        self.members.borrow_mut().insert(id, None);
        Registration {
            shutdown: self.clone(),
            id,
        }
    }

    pub(crate) fn until(&self) -> Option<SystemTime> {
        self.until.get()
    }

    /// Idempotent: the first deadline stands. A connection learns of it on
    /// its loop's next turn, which this wake makes happen now.
    pub(crate) fn begin(&self, drain_timeout: Duration) {
        if self.until.get().is_some() {
            return;
        }
        self.until
            .set(Some(runtime::runtime::now() + drain_timeout));
        // A wake only queues the task, so no member runs, or leaves, while
        // the map is borrowed.
        for shared in self.members.borrow().values().flatten() {
            shared.wake_flusher();
        }
    }

    pub(crate) fn emptied(&self) -> impl Future<Output = ()> + '_ {
        std::future::poll_fn(|cx| {
            if self.members.borrow().is_empty() {
                return Poll::Ready(());
            }
            *self.emptied.borrow_mut() = Some(cx.waker().clone());
            Poll::Pending
        })
    }
}

/// Leaves on drop, however the connection ended.
pub(crate) struct Registration {
    shutdown: Rc<Shutdown>,
    id: u64,
}

impl Registration {
    /// What `begin` wakes: the connection loop parks its waker there.
    pub(crate) fn attach(&self, shared: Rc<SharedConnection>) {
        if let Some(slot) = self.shutdown.members.borrow_mut().get_mut(&self.id) {
            *slot = Some(shared);
        }
    }

    pub(crate) fn until(&self) -> Option<SystemTime> {
        self.shutdown.until()
    }
}

impl Drop for Registration {
    fn drop(&mut self) {
        let mut members = self.shutdown.members.borrow_mut();
        members.remove(&self.id);
        let last = members.is_empty();
        drop(members);
        if last && let Some(waker) = self.shutdown.emptied.borrow_mut().take() {
            waker.wake();
        }
    }
}
