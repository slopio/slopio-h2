//! The connection's live streams, reachable from the tasks that run them.
//!
//! A stream task takes itself out of this map on the way down, so the map
//! cannot be something the connection holds by `&mut`: the removal happens
//! while the connection is suspended at an `await`, inside the destructor of
//! a future the scheduler is dropping. An `UnsafeCell` behind an `Rc` is
//! what lets both reach it.
//!
//! # Safety
//!
//! What makes that sound is two rules, and the API exists to enforce them
//! rather than ask for them.
//!
//! **A reference into the map never outlives the call that made it.**
//! [`StreamMap::get`] hands back a fresh `Rc` instead of lending one, and
//! [`StreamMap::remove`] and [`StreamMap::take_all`] hand back owned values
//! so their destructors — a `Handle` detaching its task, among them — run at
//! the caller with no borrow outstanding. Nothing here returns a reference,
//! which is the point: a borrow that escaped would still be live the next
//! time the connection yielded, which is exactly when a task may remove an
//! entry.
//!
//! **Nothing re-enters under the borrow.** The only code that runs while a
//! reference exists is `FxHashMap`'s own — and, for
//! [`StreamMap::try_for_each`], the closure it is given, which is the one
//! method that has to ask rather than enforce.
//!
//! Both rules are what the tests at the bottom check, and they check them
//! under Miri, whose Stacked Borrows model is what turns "no overlapping
//! references" from a claim into a failing test.

use std::cell::UnsafeCell;
use std::rc::Rc;

use rustc_hash::FxHashMap;

use crate::shared::connection::STREAM_ID;

/// Generic over what it stores so its safety contract can be tested against
/// a value whose destructor re-enters, which is the case that matters and
/// the one a `Handle<()>` cannot be made to demonstrate.
pub struct StreamMap<S, H> {
    live: UnsafeCell<FxHashMap<STREAM_ID, (Rc<S>, H)>>,
}

impl<S, H> StreamMap<S, H> {
    pub fn new() -> Self {
        Self {
            live: UnsafeCell::new(FxHashMap::default()),
        }
    }

    /// §5.1.2: the map only holds live streams, so its length is the current
    /// count.
    pub fn len(&self) -> usize {
        // SAFETY: the reference dies with the expression, and `len` cannot
        // re-enter.
        unsafe { (*self.live.get()).len() }
    }

    /// The stream under `id`, as a fresh `Rc` rather than a reference into
    /// the map.
    pub fn get(&self, id: STREAM_ID) -> Option<Rc<S>> {
        // SAFETY: the reference dies with the expression. `Rc::clone` only
        // touches the refcount, and cannot re-enter.
        unsafe {
            (*self.live.get())
                .get(&id)
                .map(|(stream, _)| Rc::clone(stream))
        }
    }

    pub fn insert(&self, id: STREAM_ID, stream: Rc<S>, handle: H) {
        // SAFETY: the reference dies with the expression. An insert may
        // reallocate the table, which is why no reference into it may be
        // outstanding — the rule this whole API is shaped around.
        unsafe { (*self.live.get()).insert(id, (stream, handle)) };
    }

    /// Takes a stream out, handing back what it held so the caller drops it
    /// outside the borrow.
    pub fn remove(&self, id: STREAM_ID) -> Option<(Rc<S>, H)> {
        // SAFETY: the `&mut` dies before the entry is handed back, so the
        // destructors the caller then runs — which may come straight back
        // here — find no borrow outstanding.
        unsafe { (*self.live.get()).remove(&id) }
    }

    /// Empties the map, handing back everything it held for the same reason
    /// `remove` does. A `drain` whose destructors ran inside the borrow
    /// would be a removal during iteration, which is not a subtlety.
    pub fn take_all(&self) -> Vec<(Rc<S>, H)> {
        // SAFETY: the drain completes and the reference dies before the
        // `Vec` is handed back.
        unsafe { (*self.live.get()).drain().map(|(_, entry)| entry).collect() }
    }

    /// Walks every live stream, stopping at the first error.
    ///
    /// The one method that asks rather than enforces: `f` runs while a
    /// reference into the map is live, so it must not touch this map. Its
    /// caller walks to shift send windows (§6.9.2), which wakes tasks and
    /// touches nothing here.
    pub fn try_for_each<E>(&self, mut f: impl FnMut(&Rc<S>) -> Result<(), E>) -> Result<(), E> {
        // SAFETY: the reference dies with the loop, and `f` is contracted
        // above not to re-enter.
        unsafe {
            (*self.live.get())
                .values()
                .try_for_each(|(stream, _)| f(stream))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Weak;

    /// A handle whose destructor reaches back into the map it was stored in,
    /// which is what a `StreamToken` does and what the two rules exist for.
    ///
    /// `Weak`, not `Rc`, and for a reason production shares: the map holds
    /// this value, so holding the map back would be a cycle neither ever
    /// leaves. Miri's leak check is what says so.
    struct Reentrant {
        map: Weak<StreamMap<u32, Reentrant>>,
        removes: Option<STREAM_ID>,
        log: Rc<RefCell<Vec<STREAM_ID>>>,
        id: STREAM_ID,
    }

    impl Drop for Reentrant {
        fn drop(&mut self) {
            self.log.borrow_mut().push(self.id);
            if let Some((map, id)) = self.map.upgrade().zip(self.removes) {
                // Straight back into the map, from inside a destructor the
                // map's own `remove` produced.
                drop(map.remove(id));
            }
        }
    }

    fn plain(map: &Rc<StreamMap<u32, Reentrant>>, id: STREAM_ID) -> Reentrant {
        Reentrant {
            map: Rc::downgrade(map),
            removes: None,
            log: Rc::new(RefCell::new(Vec::new())),
            id,
        }
    }

    #[test]
    fn insert_get_and_remove() {
        let map: Rc<StreamMap<u32, Reentrant>> = Rc::new(StreamMap::new());
        map.insert(1, Rc::new(11), plain(&map, 1));
        map.insert(3, Rc::new(33), plain(&map, 3));

        assert_eq!(map.len(), 2);
        assert_eq!(map.get(1).map(|s| *s), Some(11));
        assert_eq!(map.get(5).map(|s| *s), None);

        let (stream, _) = map.remove(3).expect("still there");
        assert_eq!(*stream, 33);
        assert_eq!(map.len(), 1);
        assert!(map.remove(3).is_none(), "removing twice is not an error");
    }

    #[test]
    fn a_destructor_may_remove_another_entry() {
        let map: Rc<StreamMap<u32, Reentrant>> = Rc::new(StreamMap::new());
        let log = Rc::new(RefCell::new(Vec::new()));

        map.insert(1, Rc::new(11), plain(&map, 1));
        map.insert(
            3,
            Rc::new(33),
            Reentrant {
                map: Rc::downgrade(&map),
                removes: Some(1),
                log: Rc::clone(&log),
                id: 3,
            },
        );

        // Dropping 3 takes 1 out from inside its own destructor, which is a
        // `&mut` to the map taken while one of its values is being dropped
        // by a `remove` the caller made.
        drop(map.remove(3));
        assert_eq!(*log.borrow(), vec![3]);
        assert_eq!(map.len(), 0, "the destructor's removal took effect");
    }

    #[test]
    fn a_destructor_may_remove_the_entry_it_came_from() {
        let map: Rc<StreamMap<u32, Reentrant>> = Rc::new(StreamMap::new());
        let log = Rc::new(RefCell::new(Vec::new()));

        map.insert(
            1,
            Rc::new(11),
            Reentrant {
                map: Rc::downgrade(&map),
                removes: Some(1),
                log: Rc::clone(&log),
                id: 1,
            },
        );

        // The token's own case: it is already out of the map by the time its
        // destructor asks, and asking for an absent id is a lookup like any
        // other.
        drop(map.remove(1));
        assert_eq!(*log.borrow(), vec![1]);
        assert_eq!(map.len(), 0);
    }

    #[test]
    fn take_all_runs_destructors_outside_the_borrow() {
        let map: Rc<StreamMap<u32, Reentrant>> = Rc::new(StreamMap::new());
        let log = Rc::new(RefCell::new(Vec::new()));

        for id in [1u32, 3, 5] {
            map.insert(
                id,
                Rc::new(id * 11),
                Reentrant {
                    map: Rc::downgrade(&map),
                    // Each one reaches for an id the drain already took, the
                    // way every token does when its connection dies.
                    removes: Some(id),
                    log: Rc::clone(&log),
                    id,
                },
            );
        }

        let taken = map.take_all();
        assert_eq!(taken.len(), 3);
        assert_eq!(map.len(), 0);
        // The destructors run here, at the caller, with the drain long over.
        drop(taken);
        assert_eq!(log.borrow().len(), 3);
    }

    #[test]
    fn try_for_each_walks_and_stops_at_the_first_error() {
        let map: Rc<StreamMap<u32, Reentrant>> = Rc::new(StreamMap::new());
        for id in [1u32, 3, 5] {
            map.insert(id, Rc::new(id), plain(&map, id));
        }

        let mut seen = 0;
        let all: Result<(), ()> = map.try_for_each(|_| {
            seen += 1;
            Ok(())
        });
        assert!(all.is_ok());
        assert_eq!(seen, 3);

        let stopped: Result<(), u32> = map.try_for_each(|stream| Err(**stream));
        assert!(stopped.is_err());
    }
}
