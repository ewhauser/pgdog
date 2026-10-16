//! Buffers passed between PgDog and plugins.
//!
//! [`PdSlice`] borrows memory owned by PgDog for the duration of a hook call.
//!
//! [`PdVec`] is memory allocated by the plugin and handed to PgDog in a hook's
//! output. PgDog and plugins don't share an allocator (PgDog uses jemalloc,
//! plugins use whatever they were built with), so a [`PdVec`] must only be
//! freed by the plugin that created it. It deliberately has no `Drop`
//! implementation: PgDog reads what it needs and then calls the plugin's
//! `free_*` vtable entry, which runs inside the plugin.
use std::{marker::PhantomData, mem::ManuallyDrop, ptr, slice, str};

/// Borrowed slice of `T`, valid for the duration of a hook call.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct PdSlice<'a, T> {
    data: *const T,
    len: usize,
    _lifetime: PhantomData<&'a [T]>,
}

impl<'a, T> From<&'a [T]> for PdSlice<'a, T> {
    fn from(value: &'a [T]) -> Self {
        Self {
            data: value.as_ptr(),
            len: value.len(),
            _lifetime: PhantomData,
        }
    }
}

impl<'a, T> PdSlice<'a, T> {
    /// Get the slice.
    pub fn as_slice(&self) -> &'a [T] {
        if self.len == 0 {
            return &[];
        }
        // SAFETY: Only constructed from a valid slice that outlives 'a.
        unsafe { slice::from_raw_parts(self.data, self.len) }
    }
}

impl<T> Default for PdSlice<'_, T> {
    fn default() -> Self {
        Self {
            data: ptr::null(),
            len: 0,
            _lifetime: PhantomData,
        }
    }
}

/// Values allocated by a plugin and returned to PgDog.
///
/// See the module documentation for ownership rules.
#[repr(C)]
#[derive(Debug)]
pub struct PdVec<T: Copy> {
    data: *mut T,
    len: usize,
    capacity: usize,
}

/// Bytes allocated by a plugin and returned to PgDog.
pub type PdBuf = PdVec<u8>;

impl<T: Copy> PdVec<T> {
    /// Empty buffer. Doesn't allocate.
    pub const fn empty() -> Self {
        Self {
            data: ptr::null_mut(),
            len: 0,
            capacity: 0,
        }
    }

    /// Values in the buffer.
    pub fn as_slice(&self) -> &[T] {
        if self.data.is_null() {
            return &[];
        }
        // SAFETY: Constructed from a Vec<T> with this pointer and length.
        unsafe { slice::from_raw_parts(self.data, self.len) }
    }

    /// Release the memory.
    ///
    /// # Safety
    ///
    /// Must be called by the same binary (plugin) that created the buffer,
    /// so the memory is returned to the allocator it came from.
    pub unsafe fn free(&mut self) {
        let buf = std::mem::take(self);
        if !buf.data.is_null() {
            // SAFETY: Created from a Vec<T> with these parts by this binary.
            drop(unsafe { Vec::from_raw_parts(buf.data, buf.len, buf.capacity) });
        }
    }
}

impl PdVec<u8> {
    /// Bytes in the buffer.
    pub fn as_bytes(&self) -> &[u8] {
        self.as_slice()
    }

    /// The buffer as UTF-8, if it is valid UTF-8.
    pub fn as_str(&self) -> Option<&str> {
        str::from_utf8(self.as_bytes()).ok()
    }
}

impl<T: Copy> Default for PdVec<T> {
    fn default() -> Self {
        Self::empty()
    }
}

impl<T: Copy> From<Vec<T>> for PdVec<T> {
    fn from(value: Vec<T>) -> Self {
        if value.capacity() == 0 {
            return Self::empty();
        }
        let mut value = ManuallyDrop::new(value);
        Self {
            data: value.as_mut_ptr(),
            len: value.len(),
            capacity: value.capacity(),
        }
    }
}

impl From<String> for PdVec<u8> {
    fn from(value: String) -> Self {
        Self::from(value.into_bytes())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_pd_buf_round_trip() {
        let mut buf = PdBuf::from(String::from("SELECT 1"));
        assert_eq!(buf.as_str(), Some("SELECT 1"));
        unsafe { buf.free() };
        assert!(buf.as_bytes().is_empty());
        // Double free is a no-op.
        unsafe { buf.free() };
    }

    #[test]
    fn test_pd_buf_empty() {
        let buf = PdBuf::from(Vec::new());
        assert!(buf.as_bytes().is_empty());
        assert_eq!(buf.as_str(), Some(""));
    }

    #[test]
    fn test_pd_vec() {
        let mut lengths = PdVec::from(vec![3_i32, -1, 0]);
        assert_eq!(lengths.as_slice(), &[3, -1, 0]);
        unsafe { lengths.free() };
        assert!(lengths.as_slice().is_empty());
    }

    #[test]
    fn test_pd_slice() {
        let formats: Vec<i16> = vec![0, 1];
        let slice = PdSlice::from(formats.as_slice());
        assert_eq!(slice.as_slice(), &[0, 1]);
        assert!(PdSlice::<i16>::default().as_slice().is_empty());
    }
}
