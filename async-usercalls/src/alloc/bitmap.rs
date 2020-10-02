use spin::Mutex;
use std::sync::atomic::*;

pub struct OptionalBitmap(BitmapKind);

struct LargeBitmap(Mutex<LargeBitmapInner>);

struct LargeBitmapInner {
    bits: Box<[u64]>,
    unset_count: usize, // optimization
}

enum BitmapKind {
    None,
    V1(AtomicU8),
    V2(AtomicU16),
    V3(AtomicU32),
    V4(AtomicU64),
    V5(LargeBitmap),
}

impl OptionalBitmap {
    pub fn none() -> Self {
        Self(BitmapKind::None)
    }

    /// `bit_count` must be >= 8 and a power of two
    pub fn new(bit_count: usize) -> Self {
        Self(match bit_count {
            8 => BitmapKind::V1(AtomicU8::new(0)),
            16 => BitmapKind::V2(AtomicU16::new(0)),
            32 => BitmapKind::V3(AtomicU32::new(0)),
            64 => BitmapKind::V4(AtomicU64::new(0)),
            n if n > 0 && n % 64 == 0 => {
                let bits = vec![0u64; n / 64].into_boxed_slice();
                BitmapKind::V5(LargeBitmap(Mutex::new(LargeBitmapInner {
                    bits,
                    unset_count: bit_count,
                })))
            }
            _ => panic!("bit_count must be >= 8 and a power of two"),
        })
    }

    /// set the bit at given index to 0 and panic if the old value was not 1.
    pub fn unset(&self, index: usize) {
        match self.0 {
            BitmapKind::None => {}
            BitmapKind::V1(ref a) => a.unset(index),
            BitmapKind::V2(ref b) => b.unset(index),
            BitmapKind::V3(ref c) => c.unset(index),
            BitmapKind::V4(ref d) => d.unset(index),
            BitmapKind::V5(ref e) => e.unset(index),
        }
    }

    /// return the index of a previously unset bit and set that bit to 1.
    pub fn reserve(&self) -> Option<usize> {
        match self.0 {
            BitmapKind::None => None,
            BitmapKind::V1(ref a) => a.reserve(),
            BitmapKind::V2(ref b) => b.reserve(),
            BitmapKind::V3(ref c) => c.reserve(),
            BitmapKind::V4(ref d) => d.reserve(),
            BitmapKind::V5(ref e) => e.reserve(),
        }
    }
}

trait BitmapOps {
    fn unset(&self, index: usize);
    fn reserve(&self) -> Option<usize>;
}

macro_rules! impl_bitmap_ops {
    ( $( $t:ty ),* $(,)? ) => {$(
        impl BitmapOps for $t {
            fn unset(&self, index: usize) {
                let bit = 1 << index;
                let old = self.fetch_and(!bit, Ordering::Release) & bit;
                assert!(old != 0);
            }

            fn reserve(&self) -> Option<usize> {
                let initial = self.load(Ordering::Relaxed);
                let unset_count = initial.count_zeros();
                let (mut index, mut bit) = match unset_count {
                    0 => return None,
                    _ => (0, 1),
                };
                for _ in 0..unset_count {
                    // find the next unset bit
                    while bit & initial != 0 {
                        index += 1;
                        bit = bit << 1;
                    }
                    let old = self.fetch_or(bit, Ordering::Acquire) & bit;
                    if old == 0 {
                        return Some(index);
                    }
                    index += 1;
                    bit = bit << 1;
                }
                None
            }
        }
    )*};
}

impl_bitmap_ops!(AtomicU8, AtomicU16, AtomicU32, AtomicU64);

impl BitmapOps for LargeBitmap {
    fn unset(&self, index: usize) {
        let mut inner = self.0.lock();
        let array = &mut inner.bits;
        assert!(index < array.len() * 64);
        let slot = index / 64;
        let offset = index % 64;
        let element = &mut array[slot];

        let bit = 1 << offset;
        let old = *element & bit;
        *element = *element & !bit;
        inner.unset_count += 1;
        assert!(old != 0);
    }

    fn reserve(&self) -> Option<usize> {
        let mut inner = self.0.lock();
        if inner.unset_count == 0 {
            return None;
        }
        let array = &mut inner.bits;
        for slot in 0..array.len() {
            if let (Some(offset), val) = reserve_u64(array[slot]) {
                array[slot] = val;
                inner.unset_count -= 1;
                return Some(slot * 64 + offset);
            }
        }
        unreachable!()
    }
}

fn reserve_u64(element: u64) -> (Option<usize>, u64) {
    let (mut index, mut bit) = match element.count_zeros() {
        0 => return (None, element),
        _ => (0, 1),
    };
    // find the first unset bit
    while bit & element != 0 {
        index += 1;
        bit = bit << 1;
    }
    (Some(index), element | bit)
}
