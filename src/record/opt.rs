use std::{
    fmt::{self, Display, Formatter},
    ops::Range,
};

use crate::{
    opt::Opt,
    record::{RecordClass, RecordData, RecordType},
    text::DomainName,
    wire::{to_wire, WireDecode, WireEncode, WireError, WireRead, WireWrite},
    zone::{ZoneError, ZoneErrorKind, ZoneReader},
};

/// An OPT pseudo-record
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OptRecord {
    name: DomainName,
    flags: u32,
    udp_payload_size: u16,
    options: Vec<Opt>,
}

impl OptRecord {
    pub const BITS_RESPONSE_CODE: Range<u32> = 24..32;
    pub const BITS_VERSION: Range<u32> = 16..24;
    pub const FLAG_DNSSEC_OK: u32 = 16;
    pub const BITS_ZERO: Range<u32> = 0..16;

    /// Constructs a new OPT pseudo-record
    pub fn new(name: DomainName, udp_payload_size: u16, flags: u32, options: &[Opt]) -> Self {
        Self {
            name,
            udp_payload_size,
            flags,
            options: options.to_vec(),
        }
    }

    /// The EDNS flags this record contains
    pub fn flags(&self) -> u32 {
        self.flags
    }

    /// The maximum UDP payload size to be used
    pub fn udp_payload_size(&self) -> u16 {
        self.udp_payload_size
    }

    /// The EDNS options contained in this record
    pub fn options(&self) -> &[Opt] {
        &self.options
    }
}

impl<'read> RecordData<'read> for OptRecord {
    fn data_size(&self) -> usize {
        self.options.iter().map(Opt::size).sum()
    }

    fn encode_data(&self, writer: &mut WireWrite) -> Result<(), WireError> {
        for option in &self.options {
            option.encode(writer)?;
        }
        Ok(())
    }

    fn decode_data(
        name: DomainName,
        flags: u32,
        rclass: RecordClass,
        rtype: RecordType,
        len: u16,
        reader: &mut WireRead<'read>,
    ) -> Result<Self, WireError> {
        debug_assert_eq!(rtype, RecordType::Opt);

        let mut options = Vec::new();

        let mut expected = len as isize;
        loop {
            if expected == 0 {
                break;
            }

            if expected < 0 {
                return Err(WireError::InvalidLength {
                    expected: (len as isize - expected) as usize,
                    actual: len as usize,
                });
            }

            let option = Opt::decode(reader)?;
            expected -= option.size() as isize;
            options.push(option);
        }

        Ok(Self {
            name,
            udp_payload_size: rclass.into(),
            flags,
            options,
        })
    }

    fn decode_zone(
        _: DomainName,
        _: u32,
        _: RecordClass,
        rtype: RecordType,
        reader: &mut ZoneReader,
    ) -> Result<Self, ZoneError> {
        debug_assert_eq!(rtype, RecordType::Opt);
        reader.error(ZoneErrorKind::BadEntry)
    }

    fn name(&self) -> &DomainName {
        &self.name
    }

    fn ttl(&self) -> u32 {
        self.flags
    }

    fn rclass(&self) -> RecordClass {
        self.udp_payload_size.into()
    }

    fn rtype(&self) -> RecordType {
        RecordType::Opt
    }
}

impl Display for OptRecord {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "\\# {}", self.data_size())?;
        for option in &self.options {
            write!(f, " ")?;
            for byte in to_wire(option).unwrap() {
                write!(f, "{:0>2x}", byte)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use insta::assert_debug_snapshot;

    use super::*;
    use crate::{
        opt::name_server_identifier::NameServerIdentifierOpt,
        record::Record,
        wire::{from_wire, to_wire},
    };

    #[test]
    fn wire() {
        let record = Record::Opt(OptRecord::new(
            ".".parse().unwrap(),
            1312,
            0b0000_0000_0000_0000_1000_0000_0000_0000,
            &[Opt::NameServerIdentifier(NameServerIdentifierOpt::new(&[
                b'r', b'e', b'a', b'l', b'm',
            ]))],
        ));

        let wire = to_wire(&record).unwrap();
        assert_debug_snapshot!(wire);

        assert_eq!(from_wire::<Record>(&wire), Ok(record));
    }
}
