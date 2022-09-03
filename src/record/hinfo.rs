use std::fmt::{self, Display, Formatter};

use crate::{
    record::{RecordClass, RecordData, RecordType},
    text::{DomainName, Text},
    wire::{WireDecode, WireEncode, WireError, WireRead, WireWrite},
    zone::{ZoneError, ZoneReader},
};

/// An HINFO record
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HinfoRecord {
    name: DomainName,
    ttl: u32,
    rclass: RecordClass,
    cpu: Text,
    os: Text,
}

impl HinfoRecord {
    /// Constructs a new HINFO record
    pub fn new(name: DomainName, ttl: u32, rclass: RecordClass, cpu: Text, os: Text) -> Self {
        Self {
            name,
            ttl,
            rclass,
            cpu,
            os,
        }
    }

    /// The CPU type for the host
    pub fn cpu(&self) -> &Text {
        &self.cpu
    }

    /// The OS type for the host
    pub fn os(&self) -> &Text {
        &self.os
    }
}

impl<'read> RecordData<'read> for HinfoRecord {
    fn data_size(&self) -> usize {
        self.cpu.size() + self.os.size()
    }

    fn encode_data(&self, writer: &mut WireWrite) -> Result<(), WireError> {
        self.cpu.encode(writer)?;
        self.os.encode(writer)?;

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
        debug_assert_eq!(rtype, RecordType::Hinfo);

        let cpu = Text::decode(reader)?;
        let os = Text::decode(reader)?;

        if cpu.size() + os.size() != len as usize {
            return Err(WireError::InvalidLength {
                expected: cpu.size() + os.size(),
                actual: len as usize,
            });
        }

        Ok(Self {
            name,
            ttl,
            rclass,
            cpu,
            os,
        })
    }

    fn decode_zone(
        name: DomainName,
        ttl: u32,
        rclass: RecordClass,
        rtype: RecordType,
        reader: &mut ZoneReader,
    ) -> Result<Self, ZoneError> {
        debug_assert_eq!(rtype, RecordType::Hinfo);

        let cpu = reader.read_text()?;
        reader.read_blank()?;
        let os = reader.read_text()?;

        Ok(Self {
            name,
            ttl,
            rclass,
            cpu,
            os,
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
        RecordType::Hinfo
    }
}

impl Display for HinfoRecord {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{} {}", self.cpu, self.os)
    }
}

#[cfg(test)]
mod tests {
    use insta::{assert_debug_snapshot, assert_display_snapshot};

    use super::*;
    use crate::{
        record::Record,
        wire::{from_wire, to_wire},
    };

    #[test]
    fn wire() {
        let record = Record::Hinfo(HinfoRecord::new(
            "alpha.host.example.com.".parse().unwrap(),
            86400,
            RecordClass::In,
            r#""INTEL-386""#.parse().unwrap(),
            r#""UNIX""#.parse().unwrap(),
        ));

        let wire = to_wire(&record).unwrap();
        assert_debug_snapshot!(wire);

        assert_eq!(from_wire::<Record>(&wire), Ok(record));
    }

    #[test]
    fn zone() {
        let record = Record::Hinfo(HinfoRecord::new(
            "gamma.host.example.com.".parse().unwrap(),
            86400,
            RecordClass::In,
            r#""i386""#.parse().unwrap(),
            r#""Linux""#.parse().unwrap(),
        ));

        assert_display_snapshot!(record);
    }
}
