use std::ops::{
    BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Not, Range, Shl, ShlAssign,
    Shr, ShrAssign,
};

use num_traits::{Num, NumAssign};

/// A trait that represents an integer that can be used as a bitfield
pub trait BitField:
    Num
    + Copy
    + Not<Output = Self>
    + BitAnd<Output = Self>
    + BitOr<Output = Self>
    + BitXor<Output = Self>
    + Shl<Output = Self>
    + Shr<Output = Self>
{
    /// Gets a flag at a given position
    ///
    /// # Examples
    ///
    /// ```
    /// assert!(0b1011.get_flag(0));
    /// assert!(0b1011.get_flag(1));
    /// assert!(!0b1011.get_flag(2));
    /// assert!(0b1011.get_flag(3));
    /// ```
    fn get_flag(self, bit: Self) -> bool {
        (self & (Self::one() << bit)) != Self::zero()
    }

    /// Gets a range of bits for a given range
    ///
    /// # Examples
    ///
    /// ```
    /// assert_eq!(0b1011.get_bits(0..4), 0b1011);
    /// assert_eq!(0b1011.get_bits(1..4), 0b101);
    /// assert_eq!(0b1011.get_bits(0..3), 0b011);
    /// ```
    fn get_bits(self, range: Range<Self>) -> Self {
        (self >> range.start) & ((Self::one() << (range.end - range.start)) - Self::one())
    }
}

impl<T> BitField for T where
    T: Num
        + Copy
        + Not<Output = Self>
        + BitAnd<Self, Output = Self>
        + BitOr<Self, Output = Self>
        + BitXor<Self, Output = Self>
        + Shl<Self, Output = Self>
        + Shr<Self, Output = Self>
{
}

/// A trait that represents an integer that can be used as a bitfield which also can self assign
pub trait BitFieldAssign:
    BitField
    + NumAssign
    + BitAndAssign<Self>
    + BitOrAssign<Self>
    + BitXorAssign<Self>
    + ShlAssign<Self>
    + ShrAssign<Self>
{
    /// Sets a flag at a given position
    ///
    /// # Examples
    ///
    /// ```
    /// let mut flags = 0u8;
    /// flags.set_flag(0, false);
    /// flags.set_flag(1, true);
    /// flags.set_flag(7, true);
    /// assert_eq!(flags, 0b10110010)
    /// ```
    fn set_flag(&mut self, bit: Self, value: bool) {
        if value {
            *self |= Self::one() << bit
        } else {
            *self &= !(Self::one() << bit)
        }
    }

    /// Sets a range of bits for a given range
    ///
    /// # Examples
    ///
    /// ```
    /// let mut flags = 0u8;
    /// flags.set_bits(0..4, 0b0011);
    /// flags.set_bits(2..6, 0b1111_1100);
    /// assert_eq!(flags, 0b00110011)
    /// ```
    fn set_bits(&mut self, range: Range<Self>, value: Self) {
        let bits = range.end - range.start;
        let mask = ((Self::one() << bits) - Self::one()) << range.start;
        *self &= !mask;
        *self |= (value << range.start) & mask;
    }
}

impl<T> BitFieldAssign for T where
    T: BitField + NumAssign + BitAndAssign + BitOrAssign + BitXorAssign + ShlAssign + ShrAssign
{
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get() {
        assert!(0b1011.get_flag(0));
        assert!(0b1011.get_flag(1));
        assert!(!0b1011.get_flag(2));
        assert!(0b1011.get_flag(3));

        assert_eq!(0b1011.get_bits(0..4), 0b1011);
        assert_eq!(0b1011.get_bits(1..4), 0b101);
        assert_eq!(0b1011.get_bits(0..3), 0b011);
    }

    #[test]
    fn set() {
        let mut flags = 0u8;

        flags.set_flag(0, false);
        flags.set_flag(1, true);
        flags.set_bits(2..6, 0b1111_1100);
        flags.set_flag(7, true);

        assert_eq!(flags, 0b10110010)
    }
}
