//! A stream task removes itself from this map inside the destructor of a
//! future dropped while the connection is suspended, so the map is an
//! `UnsafeCell` behind an `Rc`.
//!
//! # Safety
//!
//! **A reference into the map never outlives the call that made it.** Nothing
//! here returns a reference: [`StreamMap::get`] hands back a fresh `Rc`, and
//! [`StreamMap::remove`] and [`StreamMap::take_all`] hand back owned values so
//! their destructors run at the caller with no borrow outstanding. An escaped
//! borrow would still be live the next time the connection yielded, which is
//! exactly when a task may remove an entry.
//!
//! **Nothing re-enters under the borrow.** Only `FxHashMap`'s own code runs —
//! and, for [`StreamMap::try_for_each`], its closure, the one method that has
//! to ask rather than enforce.
//!
//! The tests at the bottom check both rules under Miri (Stacked Borrows).

use std::cell::UnsafeCell;
use std::rc::Rc;

use rustc_hash::FxHashMap;

use crate::shared::connection::STREAM_ID;

/// Generic so the safety contract can be tested against a value whose
/// destructor re-enters.
pub struct StreamMap<S, H> {
    live: UnsafeCell<FxHashMap<STREAM_ID, (Rc<S>, H)>>,
}

impl<S, H> StreamMap<S, H> {
    pub fn new() -> Self {
        Self {
            live: UnsafeCell::new(FxHashMap::default()),
        }
    }

    /// §5.1.2: the map only holds live streams.
    pub fn len(&self) -> usize {
        // SAFETY: the reference dies with the expression, and `len` cannot
        // re-enter.
        unsafe { (*self.live.get()).len() }
    }

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
        // reallocate the table, so no reference into it may be outstanding.
        unsafe { (*self.live.get()).insert(id, (stream, handle)) };
    }

    pub fn remove(&self, id: STREAM_ID) -> Option<(Rc<S>, H)> {
        // SAFETY: the `&mut` dies before the entry is handed back, so the
        // destructors the caller then runs — which may come straight back
        // here — find no borrow outstanding.
        unsafe { (*self.live.get()).remove(&id) }
    }

    /// Destructors run inside a `drain` would be a removal during iteration.
    pub fn take_all(&self) -> Vec<(Rc<S>, H)> {
        // SAFETY: the drain completes and the reference dies before the
        // `Vec` is handed back.
        unsafe { (*self.live.get()).drain().map(|(_, entry)| entry).collect() }
    }

    /// `f` runs while a reference into the map is live, so it must not touch
    /// this map.
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

    /// `Weak`, not `Rc`: holding the map back would be a cycle, which Miri's
    /// leak check catches.
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
                    removes: Some(id),
                    log: Rc::clone(&log),
                    id,
                },
            );
        }

        let taken = map.take_all();
        assert_eq!(taken.len(), 3);
        assert_eq!(map.len(), 0);
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
