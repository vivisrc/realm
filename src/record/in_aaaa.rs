use std::{
    fmt::{self, Display, Formatter},
    net::Ipv6Addr,
};

use crate::{
    record::{RecordClass, RecordData, RecordType},
    text::DomainName,
    wire::{WireDecode, WireEncode, WireError, WireRead, WireWrite},
    zone::{ZoneError, ZoneReader},
};

/// An AAAA record for the IN class
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InAaaaRecord {
    name: DomainName,
    ttl: u32,
    addr: Ipv6Addr,
}

impl InAaaaRecord {
    /// Constructs a new AAAA record for the IN class
    pub fn new(name: DomainName, ttl: u32, addr: Ipv6Addr) -> Self {
        Self { name, ttl, addr }
    }

    /// The IPv6 address
    pub fn addr(&self) -> Ipv6Addr {
        self.addr
    }
}

impl<'read> RecordData<'read> for InAaaaRecord {
    fn data_size(&self) -> usize {
        16
    }

    fn encode_data(&self, writer: &mut WireWrite) -> Result<(), WireError> {
        u128::from(self.addr).encode(writer)
    }

    fn decode_data(
        name: DomainName,
        ttl: u32,
        rclass: RecordClass,
        rtype: RecordType,
        len: u16,
        reader: &mut WireRead<'read>,
    ) -> Result<Self, WireError> {
        debug_assert_eq!(rclass, RecordClass::In);
        debug_assert_eq!(rtype, RecordType::Aaaa);

        if len != 16 {
            return Err(WireError::InvalidLength {
                expected: 16,
                actual: len as usize,
            });
        }

        Ok(Self {
            name,
            ttl,
            addr: u128::decode(reader)?.into(),
        })
    }

    fn decode_zone(
        name: DomainName,
        ttl: u32,
        rclass: RecordClass,
        rtype: RecordType,
        reader: &mut ZoneReader,
    ) -> Result<Self, ZoneError> {
        debug_assert_eq!(rclass, RecordClass::In);
        debug_assert_eq!(rtype, RecordType::Aaaa);

        let addr = reader.read_parsable()?;

        Ok(Self { name, ttl, addr })
    }

    fn name(&self) -> &DomainName {
        &self.name
    }

    fn ttl(&self) -> u32 {
        self.ttl
    }

    fn rclass(&self) -> RecordClass {
        RecordClass::In
    }

    fn rtype(&self) -> RecordType {
        RecordType::Aaaa
    }
}

impl Display for InAaaaRecord {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}", self.addr)
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
        let record = Record::InAaaa(InAaaaRecord::new(
            "omicron.host.example.com.".parse().unwrap(),
            3600,
            Ipv6Addr::new(0x2001, 0xdb2, 0, 0x40, 0, 0, 0, 1),
        ));

        let wire = to_wire(&record).unwrap();
        assert_debug_snapshot!(wire);

        assert_eq!(from_wire::<Record>(&wire), Ok(record));
    }

    #[test]
    fn zone() {
        let record = Record::InAaaa(InAaaaRecord::new(
            "iota.host.example.com.".parse().unwrap(),
            3600,
            Ipv6Addr::new(0x2001, 0xdb2, 0, 0x30, 0, 0, 0, 1),
        ));

        assert_display_snapshot!(record);

        let mut root = Node::new();
        root.insert(Label::from(b"com".to_vec()))
            .insert(Label::from(b"example".to_vec()))
            .insert(Label::from(b"host".to_vec()))
            .insert(Label::from(b"iota".to_vec()))
            .add_record(record.clone());

        assert_eq!(read_zone(&record.to_string(), Vec::new().into()), Ok(root));
    }
}
