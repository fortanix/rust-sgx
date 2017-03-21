use core::mem::size_of;
use core::num::Wrapping;

/// Basic power-of-2 integer math.
pub trait PowersOf2 {
    fn is_power_of_2(self) -> bool;
    fn next_power_of_2(self) -> usize;
    fn log2(self) -> u8;
}

impl PowersOf2 for usize {
    /// This code is based on
    /// http://graphics.stanford.edu/~seander/bithacks.html#DetermineIfPowerOf2
    fn is_power_of_2(self) -> bool {
        self !=0 && (self & (self - 1)) == 0
    }

    /// Caluculate the next power of two.
    ///
    /// Based on
    /// http://graphics.stanford.edu/~seander/bithacks.html#RoundUpPowerOf2
    fn next_power_of_2(self) -> usize {
        // Pick off this immediately in hopes that the optimizer can see it
        // easily.
        if self == 0 { return 1; }

        let mut v = Wrapping(self);

        v = v - Wrapping(1);
        v = v | (v >> 1);
        v = v | (v >> 2);
        v = v | (v >> 4);
        v = v | (v >> 8);
        v = v | (v >> 16);
        if size_of::<usize>() > 4 {
            v = v | (v >> 32);
        }
        v = v + Wrapping(1);

        let result = match v { Wrapping(v) => v };
        assert!(result.is_power_of_2());
        assert!(result >= self && self > result >> 1);
        result
    }

    /// Calculate the base-2 logarithm of this value.
    ///
    /// This will normally round down, except for the case of `0.log2()`,
    /// which will return 0.
    ///
    /// Based on the obvious code at
    /// http://graphics.stanford.edu/~seander/bithacks.html#IntegerLogObvious
    fn log2(self) -> u8 {
        let mut temp = self;
        let mut result = 0;
        temp >>= 1;
        while temp != 0 {
            result += 1;
            temp >>= 1;
        }
        result
    }
}

#[test]
fn test_is_power_of_2() {
    assert_eq!(false, 0.is_power_of_2());
    assert_eq!(true,  1.is_power_of_2());
    assert_eq!(true,  2.is_power_of_2());
    assert_eq!(false, 3.is_power_of_2());
    assert_eq!(true,  4.is_power_of_2());
    assert_eq!(false, 255.is_power_of_2());
    assert_eq!(true,  256.is_power_of_2());
    assert_eq!(false, 257.is_power_of_2());
    assert_eq!(false, 4294967295.is_power_of_2());
    if size_of::<usize>() > 4 {
        assert_eq!(false, 18446744073709551615.is_power_of_2());
    }
}

#[test]
fn test_next_power_of_2() {
    assert_eq!(1,  0.next_power_of_2());
    assert_eq!(1,  1.next_power_of_2());
    assert_eq!(2,  2.next_power_of_2());
    assert_eq!(4,  3.next_power_of_2());
    assert_eq!(4,  4.next_power_of_2());
    assert_eq!(8,  5.next_power_of_2());
    assert_eq!(8,  8.next_power_of_2());
    assert_eq!(16, 9.next_power_of_2());
    assert_eq!(16, 16.next_power_of_2());
    assert_eq!(32, 17.next_power_of_2());
    assert_eq!(32, 32.next_power_of_2());
    assert_eq!(8388608, 8376263.next_power_of_2());
}

#[test]
fn test_log2() {
    assert_eq!(0, 0.log2());
    assert_eq!(0, 1.log2());
    assert_eq!(1, 2.log2());
    assert_eq!(5, 32.log2());
    assert_eq!(10, 1024.log2());
}
