use std::fmt::{self, Display, Formatter};

use crate::{
    record::{RecordClass, RecordData, RecordType},
    text::{DomainName, HostName},
    wire::{WireDecode, WireEncode, WireError, WireRead, WireWrite},
    zone::{ZoneError, ZoneErrorKind, ZoneReader},
};

/// An A record for the CH class
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChARecord {
    name: DomainName,
    ttl: u32,
    network: HostName,
    addr: u16,
}

impl ChARecord {
    /// Constructs a new A record for the CH class
    pub fn new(name: DomainName, ttl: u32, network: HostName, addr: u16) -> Self {
        Self {
            name,
            ttl,
            network,
            addr,
        }
    }

    /// The domain wherein the address resides
    pub fn network(&self) -> &HostName {
        &self.network
    }

    /// The chaos address of the network
    pub fn addr(&self) -> u16 {
        self.addr
    }
}

impl<'read> RecordData<'read> for ChARecord {
    fn data_size(&self) -> usize {
        self.network.size() + 2
    }

    fn encode_data(&self, writer: &mut WireWrite) -> Result<(), WireError> {
        self.network.encode(writer)?;
        self.addr.encode(writer)?;
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
        debug_assert_eq!(rclass, RecordClass::Ch);
        debug_assert_eq!(rtype, RecordType::A);

        let network = HostName::decode(reader)?;

        if network.size() + 2 != len as usize {
            return Err(WireError::InvalidLength {
                expected: network.size() + 2,
                actual: len as usize,
            });
        }

        Ok(Self {
            name,
            ttl,
            network,
            addr: u16::decode(reader)?,
        })
    }

    fn decode_zone(
        name: DomainName,
        ttl: u32,
        rclass: RecordClass,
        rtype: RecordType,
        reader: &mut ZoneReader,
    ) -> Result<Self, ZoneError> {
        debug_assert_eq!(rclass, RecordClass::Ch);
        debug_assert_eq!(rtype, RecordType::A);

        let network = reader.read_name()?.into();
        reader.read_blank()?;
        let addr = match u16::from_str_radix(&reader.read_string()?, 8) {
            Ok(addr) => addr,
            Err(_) => return reader.error(ZoneErrorKind::BadEntry),
        };

        Ok(Self {
            name,
            ttl,
            network,
            addr,
        })
    }

    fn name(&self) -> &DomainName {
        &self.name
    }

    fn ttl(&self) -> u32 {
        self.ttl
    }

    fn rclass(&self) -> RecordClass {
        RecordClass::Ch
    }

    fn rtype(&self) -> RecordType {
        RecordType::A
    }
}

impl Display for ChARecord {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{} {:o}", self.network, self.addr)
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
        let record = Record::ChA(ChARecord::new(
            "delta.host.example.com.".parse().unwrap(),
            3600,
            "host.example.com.".parse().unwrap(),
            0o720,
        ));

        let wire = to_wire(&record).unwrap();
        assert_debug_snapshot!(wire);

        assert_eq!(from_wire::<Record>(&wire), Ok(record));
    }

    #[test]
    fn zone() {
        let record = Record::ChA(ChARecord::new(
            "gamma.host.example.com.".parse().unwrap(),
            3600,
            "host.example.com.".parse().unwrap(),
            0o710,
        ));

        assert_display_snapshot!(record);

        let mut root = Node::new();
        root.insert(Label::from(b"com".to_vec()))
            .insert(Label::from(b"example".to_vec()))
            .insert(Label::from(b"host".to_vec()))
            .insert(Label::from(b"gamma".to_vec()))
            .add_record(record.clone());

        assert_eq!(read_zone(&record.to_string(), Vec::new().into()), Ok(root));
    }
}
