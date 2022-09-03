use std::{
    fmt::{self, Display, Formatter},
    net::Ipv4Addr,
};

use crate::{
    record::{RecordClass, RecordData, RecordType},
    text::DomainName,
    wire::{WireDecode, WireEncode, WireError, WireRead, WireWrite},
    zone::{ZoneError, ZoneReader},
};

/// An A record for the IN class
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InARecord {
    name: DomainName,
    ttl: u32,
    addr: Ipv4Addr,
}

impl InARecord {
    /// Constructs a new A record for the IN class
    pub fn new(name: DomainName, ttl: u32, addr: Ipv4Addr) -> Self {
        Self { name, ttl, addr }
    }

    /// The IPv4 address
    pub fn addr(&self) -> Ipv4Addr {
        self.addr
    }
}

impl<'read> RecordData<'read> for InARecord {
    fn data_size(&self) -> usize {
        4
    }

    fn encode_data(&self, writer: &mut WireWrite) -> Result<(), WireError> {
        u32::from(self.addr).encode(writer)
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
        debug_assert_eq!(rtype, RecordType::A);

        if len != 4 {
            return Err(WireError::InvalidLength {
                expected: 4,
                actual: len as usize,
            });
        }

        Ok(Self {
            name,
            ttl,
            addr: u32::decode(reader)?.into(),
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
        debug_assert_eq!(rtype, RecordType::A);

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
        RecordType::A
    }
}

impl Display for InARecord {
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
        let record = Record::InA(InARecord::new(
            "omicron.host.example.com.".parse().unwrap(),
            3600,
            Ipv4Addr::new(192, 0, 2, 2),
        ));

        let wire = to_wire(&record).unwrap();
        assert_debug_snapshot!(wire);

        assert_eq!(from_wire::<Record>(&wire), Ok(record));
    }

    #[test]
    fn zone() {
        let record = Record::InA(InARecord::new(
            "iota.host.example.com.".parse().unwrap(),
            3600,
            Ipv4Addr::new(192, 0, 2, 1),
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
