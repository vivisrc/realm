use std::{
    fmt::{self, Debug, Display, Formatter},
    str::FromStr,
};

use num_traits::{FromPrimitive, Num};

use crate::{
    record::{RecordClass, RecordData, RecordType},
    text::DomainName,
    wire::{WireDecode, WireEncode, WireError, WireRead, WireWrite},
    zone::{ZoneError, ZoneErrorKind, ZoneReader},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Size {
    base: u8,
    exponent: u8,
}

/// A size in centimeters represented as a base and an exponent both ranging 0 to 9 inclusive
impl Size {
    /// Creates a new size
    pub fn new(base: u8, exponent: u8) -> Self {
        debug_assert!(
            (0..=9).contains(&base),
            "Size base must be 0 to 9 inclusive, got {}",
            base,
        );
        debug_assert!(
            (0..=9).contains(&exponent),
            "Size exponent must be 0 to 9 inclusive, got {}",
            exponent,
        );

        Self { base, exponent }
    }

    /// The base of this size
    pub fn base(&self) -> u8 {
        self.base
    }

    /// The exponent of this size
    pub fn exponent(&self) -> u8 {
        self.exponent
    }
}

impl WireEncode for Size {
    fn size(&self) -> usize {
        1
    }

    fn encode(&self, writer: &mut WireWrite) -> Result<(), WireError> {
        ((self.base << 4) | self.exponent).encode(writer)
    }
}

impl<'read> WireDecode<'read> for Size {
    fn decode(reader: &mut WireRead<'read>) -> Result<Self, WireError> {
        let value = u8::decode(reader)?;

        let base = value >> 4;
        let exponent = value & 0b1111;

        if !(0..=9).contains(&base) || !(0..=9).contains(&exponent) {
            return Err(WireError::UnsupportedFormat);
        }

        Ok(Self { base, exponent })
    }
}

impl From<u64> for Size {
    fn from(size: u64) -> Self {
        if size == 0 {
            return Self {
                base: 0,
                exponent: 0,
            };
        }

        let mut base = size;
        let mut exponent = 0;

        while base >= 10 {
            base /= 10;
            exponent += 1;
        }

        Self {
            base: base as u8,
            exponent,
        }
    }
}

impl From<Size> for u64 {
    fn from(size: Size) -> Self {
        size.base as u64 * 10u64.pow(size.exponent as u32)
    }
}

/// A LOC record
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocRecord {
    name: DomainName,
    ttl: u32,
    rclass: RecordClass,
    version: u8,
    latitude: i32,
    longitude: i32,
    altitude: u32,
    size: Size,
    horizontal_precision: Size,
    vertical_precision: Size,
}

impl LocRecord {
    /// Constructs a new LOC record
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        name: DomainName,
        ttl: u32,
        rclass: RecordClass,
        version: u8,
        latitude: i32,
        longitude: i32,
        altitude: u32,
        size: Size,
        horizontal_precision: Size,
        vertical_precision: Size,
    ) -> Self {
        Self {
            name,
            ttl,
            rclass,
            version,
            latitude,
            longitude,
            altitude,
            size,
            horizontal_precision,
            vertical_precision,
        }
    }

    /// The version number of the data representation
    pub fn version(&self) -> u8 {
        self.version
    }

    /// The latitude of the entity in milliarcsecond where 0 represents the equator
    pub fn latitude(&self) -> i32 {
        self.latitude
    }

    /// The longitude of the entity in milliarcsecond where 0 represents the prime meridian
    pub fn longitude(&self) -> i32 {
        self.longitude
    }

    /// The altitude of the entity in centimeters subtracted by 100 kilometers
    pub fn altitude(&self) -> u32 {
        self.altitude
    }

    /// Diameter sphere enclosing the entity
    pub fn size(&self) -> Size {
        self.size
    }

    /// Horizontal precision diameter of the location data
    pub fn horizontal_precision(&self) -> Size {
        self.horizontal_precision
    }

    /// Vertical precision diameter of the location data
    pub fn vertical_precision(&self) -> Size {
        self.vertical_precision
    }
}

const SIGN_BIT: i32 = 1 << 31;

impl<'read> RecordData<'read> for LocRecord {
    fn data_size(&self) -> usize {
        16
    }

    fn encode_data(&self, writer: &mut WireWrite) -> Result<(), WireError> {
        self.version.encode(writer)?;
        self.size.encode(writer)?;
        self.horizontal_precision.encode(writer)?;
        self.vertical_precision.encode(writer)?;
        (SIGN_BIT ^ self.latitude).encode(writer)?;
        (SIGN_BIT ^ self.longitude).encode(writer)?;
        self.altitude.encode(writer)?;

        Ok(())
    }

    fn decode_data(
        name: DomainName,
        ttl: u32,
        rclass: RecordClass,
        rtype: RecordType,
        len: u16,
        reader: &mut WireRead<'read>,
    ) -> Result<Self, WireError> {
        debug_assert_eq!(rtype, RecordType::Loc);

        if len as usize != 16 {
            return Err(WireError::InvalidLength {
                expected: 16,
                actual: len as usize,
            });
        }

        let version = u8::decode(reader)?;
        if version != 0 {
            return Err(WireError::UnsupportedFormat);
        }

        let size = Size::decode(reader)?;
        let horizontal_precision = Size::decode(reader)?;
        let vertical_precision = Size::decode(reader)?;
        let latitude = i32::decode(reader)? ^ SIGN_BIT;
        let longitude = i32::decode(reader)? ^ SIGN_BIT;
        let altitude = u32::decode(reader)?;

        Ok(Self {
            name,
            ttl,
            rclass,
            version,
            latitude,
            longitude,
            altitude,
            size,
            horizontal_precision,
            vertical_precision,
        })
    }

    fn decode_zone(
        name: DomainName,
        ttl: u32,
        rclass: RecordClass,
        rtype: RecordType,
        reader: &mut ZoneReader,
    ) -> Result<Self, ZoneError> {
        debug_assert_eq!(rtype, RecordType::Loc);

        let latitude = parse_milliarcsecond(reader, 90, "N", "S")?;
        reader.read_blank()?;
        let longitude = parse_milliarcsecond(reader, 180, "E", "W")?;

        reader.read_blank()?;
        let altitude = match (parse_meters::<i64>(reader)? + 10000000).try_into() {
            Ok(altitude) => altitude,
            Err(_) => return reader.error(ZoneErrorKind::BadEntry),
        };

        let size = match reader.read_blank() {
            Ok(_) => Size::from(parse_meters::<u64>(reader)?),
            Err(err) if *err.kind() == ZoneErrorKind::IncompleteEntry => Size::new(1, 2),
            Err(err) => return Err(err),
        };

        let horizontal_precision = match reader.read_blank() {
            Ok(_) => Size::from(parse_meters::<u64>(reader)?),
            Err(err) if *err.kind() == ZoneErrorKind::IncompleteEntry => Size::new(1, 6),
            Err(err) => return Err(err),
        };

        let vertical_precision = match reader.read_blank() {
            Ok(_) => Size::from(parse_meters::<u64>(reader)?),
            Err(err) if *err.kind() == ZoneErrorKind::IncompleteEntry => Size::new(1, 3),
            Err(err) => return Err(err),
        };

        Ok(Self {
            name,
            ttl,
            rclass,
            version: 0,
            latitude,
            longitude,
            altitude,
            size,
            horizontal_precision,
            vertical_precision,
        })
    }

    fn name(&self) -> &DomainName {
        &self.name
    }

    fn ttl(&self) -> u32 {
        self.ttl
    }

    fn rclass(&self) -> RecordClass {
        self.rclass
    }

    fn rtype(&self) -> RecordType {
        RecordType::Loc
    }
}

fn parse_milliarcsecond<'source>(
    reader: &mut ZoneReader<'source>,
    bound: i32,
    pos: &'static str,
    neg: &'static str,
) -> Result<i32, ZoneError> {
    let mut milliarcseconds = reader.read_parsable::<i32>()? * 3600000;
    if milliarcseconds > bound * 3600000 {
        return reader.error(ZoneErrorKind::BadEntry);
    }

    reader.read_blank()?;
    let maybe_minutes = reader.read_string()?;
    match maybe_minutes.parse::<i32>() {
        Ok(minutes) if (0..60).contains(&minutes) => milliarcseconds += minutes * 60000,
        Err(_) if maybe_minutes == pos => return Ok(milliarcseconds),
        Err(_) if maybe_minutes == neg => return Ok(-milliarcseconds),
        _ => return reader.error(ZoneErrorKind::BadEntry),
    };

    reader.read_blank()?;
    let maybe_seconds = reader.read_string()?;
    match maybe_seconds.parse::<f64>() {
        Ok(seconds) if (0.0..60.0).contains(&seconds) => {
            milliarcseconds += (seconds * 1000.0).floor() as i32
        }
        Err(_) if maybe_seconds == pos => return Ok(milliarcseconds),
        Err(_) if maybe_seconds == neg => return Ok(-milliarcseconds),
        _ => return reader.error(ZoneErrorKind::BadEntry),
    };

    reader.read_blank()?;
    let direction = reader.read_string()?;

    if direction == pos {
        return Ok(milliarcseconds);
    }
    if direction == neg {
        return Ok(-milliarcseconds);
    }

    reader.error(ZoneErrorKind::BadEntry)
}

fn format_milliarcsecond(milliarcsecond: i32, pos: char, neg: char) -> String {
    let suffix = if milliarcsecond >= 0 { pos } else { neg };

    let degrees_precise = milliarcsecond as f64 / 3600000.0;

    let absolute = degrees_precise.abs();
    let degrees = absolute.floor();

    let fract = absolute - degrees;
    let minutes = (60.0 * fract).floor();
    let seconds = 3600.0 * fract - 60.0 * minutes;

    format!("{} {} {:.3} {}", degrees, minutes, seconds, suffix)
}

fn parse_meters<T>(reader: &mut ZoneReader) -> Result<T, ZoneError>
where
    T: Num + FromPrimitive + FromStr + Debug,
{
    let (mut value, measurement) = reader.read_measure::<f64>()?;

    if !measurement.is_empty() && measurement != "m" {
        println!("not m or empty");
        return reader.error(ZoneErrorKind::BadEntry);
    }

    value *= 100.0;

    match T::from_f64(value) {
        Some(value) => Ok(value),
        None => reader.error(ZoneErrorKind::BadEntry),
    }
}

impl Display for LocRecord {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(
            f,
            "{} {} {:.2}m {:.2}m {:.2}m {:.2}m",
            format_milliarcsecond(self.latitude, 'N', 'S'),
            format_milliarcsecond(self.longitude, 'E', 'W'),
            (self.altitude as f64) / 100.0 - 100000.0,
            (u64::from(self.size) as f64) / 100.0,
            (u64::from(self.horizontal_precision) as f64) / 100.0,
            (u64::from(self.vertical_precision) as f64) / 100.0,
        )
    }
}

#[cfg(test)]
mod tests {
    use insta::{assert_debug_snapshot, assert_display_snapshot};

    use super::*;
    use crate::{
        node::Node,
        record::Record,
        text::Label,
        wire::{from_wire, to_wire},
        zone::read_zone,
    };

    #[test]
    fn wire() {
        let record = Record::Loc(LocRecord::new(
            "rho.host.example.com.".parse().unwrap(),
            86400,
            RecordClass::In,
            0,
            152488764,
            255651617,
            9995600,
            Size::new(2, 5),
            Size::new(1, 6),
            Size::new(1, 3),
        ));

        let wire = to_wire(&record).unwrap();
        assert_debug_snapshot!(wire);

        assert_eq!(from_wire::<Record>(&wire), Ok(record));
    }

    #[test]
    fn zone() {
        let record = Record::Loc(LocRecord::new(
            "sigma.host.example.com.".parse().unwrap(),
            86400,
            RecordClass::In,
            0,
            152503952,
            -255906344,
            9997600,
            Size::new(1, 2),
            Size::new(2, 4),
            Size::new(1, 3),
        ));

        assert_display_snapshot!(record);

        let mut root = Node::new();
        root.insert(Label::from(b"com".to_vec()))
            .insert(Label::from(b"example".to_vec()))
            .insert(Label::from(b"host".to_vec()))
            .insert(Label::from(b"sigma".to_vec()))
            .add_record(record.clone());

        assert_eq!(read_zone(&record.to_string(), Vec::new().into()), Ok(root));
    }

    #[test]
    fn zone_default_size() {
        assert_debug_snapshot!(read_zone(
            ". 3600 IN LOC 1 2 3 N 4 5 6 E 7m",
            Vec::new().into(),
        ))
    }

    #[test]
    fn zone_default_hp() {
        assert_debug_snapshot!(read_zone(
            ". 3600 IN LOC 1 2 3 N 4 5 6 E 7m 8m",
            Vec::new().into(),
        ))
    }

    #[test]
    fn zone_default_vp() {
        assert_debug_snapshot!(read_zone(
            ". 3600 IN LOC 1 2 3 N 4 5 6 E 7m 8m 9m",
            Vec::new().into(),
        ))
    }

    #[test]
    fn zone_no_minutes() {
        assert_debug_snapshot!(read_zone(
            ". 3600 IN LOC 1 N 2 E 3m 4m 5m 6m",
            Vec::new().into(),
        ))
    }

    #[test]
    fn zone_no_seconds() {
        assert_debug_snapshot!(read_zone(
            ". 3600 IN LOC 1 2 N 3 4 E 5m 6m 7m 8m",
            Vec::new().into(),
        ))
    }
}
