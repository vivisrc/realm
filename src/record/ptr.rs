use std::fmt::{self, Display, Formatter};

use crate::{
    record::{RecordClass, RecordData, RecordType},
    text::{DomainName, HostName},
    wire::{WireDecode, WireEncode, WireError, WireRead, WireWrite},
    zone::{ZoneError, ZoneReader},
};

/// A PTR record
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PtrRecord {
    name: DomainName,
    ttl: u32,
    rclass: RecordClass,
    pointer: HostName,
}

impl PtrRecord {
    /// Constructs a new PTR record
    pub fn new(name: DomainName, ttl: u32, rclass: RecordClass, pointer: HostName) -> Self {
        Self {
            name,
            ttl,
            rclass,
            pointer,
        }
    }

    /// The name this record points to
    pub fn pointer(&self) -> &HostName {
        &self.pointer
    }
}

impl<'read> RecordData<'read> for PtrRecord {
    fn data_size(&self) -> usize {
        self.pointer.size()
    }

    fn encode_data(&self, writer: &mut WireWrite) -> Result<(), WireError> {
        self.pointer.encode(writer)
    }

    fn decode_data(
        name: DomainName,
        ttl: u32,
        rclass: RecordClass,
        rtype: RecordType,
        len: u16,
        reader: &mut WireRead<'read>,
    ) -> Result<Self, WireError> {
        debug_assert_eq!(rtype, RecordType::Ptr);

        let pointer = HostName::decode(reader)?;

        if pointer.size() != len as usize {
            return Err(WireError::InvalidLength {
                expected: pointer.size(),
                actual: len as usize,
            });
        }

        Ok(Self {
            name,
            ttl,
            rclass,
            pointer,
        })
    }

    fn decode_zone(
        name: DomainName,
        ttl: u32,
        rclass: RecordClass,
        rtype: RecordType,
        reader: &mut ZoneReader,
    ) -> Result<Self, ZoneError> {
        debug_assert_eq!(rtype, RecordType::Ptr);

        let pointer = reader.read_name()?.into();

        Ok(Self {
            name,
            ttl,
            rclass,
            pointer,
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
        RecordType::Ptr
    }
}

impl Display for PtrRecord {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}", self.pointer)
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
        let record = Record::Ptr(PtrRecord::new(
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.4.0.0.0.0.0.0.2.b.d.0.1.0.0.2.ip6.arpa."
                .parse()
                .unwrap(),
            86400,
            RecordClass::In,
            "omicron.host.example.com.".parse().unwrap(),
        ));

        let wire = to_wire(&record).unwrap();
        assert_debug_snapshot!(wire);

        assert_eq!(from_wire::<Record>(&wire), Ok(record));
    }

    #[test]
    fn zone() {
        let record = Record::Ptr(PtrRecord::new(
            "1.2.0.192.in-addr.arpa.".parse().unwrap(),
            86400,
            RecordClass::In,
            "iota.host.example.com.".parse().unwrap(),
        ));

        assert_display_snapshot!(record);

        let mut root = Node::new();
        root.insert(Label::from(b"arpa".to_vec()))
            .insert(Label::from(b"in-addr".to_vec()))
            .insert(Label::from(b"192".to_vec()))
            .insert(Label::from(b"0".to_vec()))
            .insert(Label::from(b"2".to_vec()))
            .insert(Label::from(b"1".to_vec()))
            .add_record(record.clone());

        assert_eq!(read_zone(&record.to_string(), Vec::new().into()), Ok(root));
    }
}
