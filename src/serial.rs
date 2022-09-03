use std::{
    cmp::Ordering,
    ops::{Add, AddAssign},
};

/// A serial number that follows the rules of serial number arithmetic described in RFC 1982
#[derive(Debug, Clone, Copy)]
pub struct Serial(u32);

impl Serial {
    pub const COMPARISON_THRESHOLD: u32 = 2u32.pow(32 - 1);
}

impl From<u32> for Serial {
    fn from(serial: u32) -> Self {
        Self(serial)
    }
}

impl From<Serial> for u32 {
    fn from(serial: Serial) -> Self {
        serial.0
    }
}

impl PartialEq for Serial {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for Serial {}

impl PartialOrd for Serial {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        if self.0 == other.0 {
            return Some(Ordering::Equal);
        }

        if (self.0 < other.0 && other.0 - self.0 < Self::COMPARISON_THRESHOLD)
            || (self.0 > other.0 && self.0 - other.0 > Self::COMPARISON_THRESHOLD)
        {
            return Some(Ordering::Less);
        }

        if (self.0 < other.0 && other.0 - self.0 > Self::COMPARISON_THRESHOLD)
            || (self.0 > other.0 && self.0 - other.0 < Self::COMPARISON_THRESHOLD)
        {
            return Some(Ordering::Greater);
        }

        None
    }
}

impl Add<u32> for Serial {
    type Output = Serial;

    fn add(self, rhs: u32) -> Self::Output {
        Serial(self.0.wrapping_add(rhs))
    }
}

impl AddAssign<u32> for Serial {
    fn add_assign(&mut self, rhs: u32) {
        *self = Serial(self.0.wrapping_add(rhs))
    }
}

#[cfg(test)]
mod tests {
    use test_case::test_case;

    use super::*;

    #[test_case(Serial(300), Serial(500) => Some(Ordering::Less); "lt")]
    #[test_case(Serial(800), Serial(700) => Some(Ordering::Greater); "gt")]
    #[test_case(Serial(100), Serial(100) => Some(Ordering::Equal); "eq")]
    #[test_case(Serial(u32::MAX), Serial(500) => Some(Ordering::Less); "overflow_lt")]
    #[test_case(Serial(800), Serial(u32::MAX) => Some(Ordering::Greater); "overflow_gt")]
    #[test_case(Serial(0), Serial(1 << 31) => None; "out_of_range")]
    fn compare(left: Serial, right: Serial) -> Option<Ordering> {
        left.partial_cmp(&right)
    }
}
