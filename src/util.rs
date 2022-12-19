//! This module is exposed only to the crate itself.

pub fn take_array_ref<T, const N: usize>(slice: &[T]) -> Option<(&[T; N], &[T])> {
    if slice.len() < N {
        return None;
    }
    let (a, b) = slice.split_at(N);
    let a = a.try_into().unwrap();
    Some((a, b))
}
