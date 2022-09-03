use std::fmt::{self, Display, Formatter};

use crate::{
    question::Question,
    record::{RecordClass, RecordData, RecordType},
    resolver::ResolveType,
    text::{DomainName, HostName},
    wire::{WireDecode, WireEncode, WireError, WireRead, WireWrite},
    zone::{ZoneError, ZoneReader},
};

/// An NS record
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NsRecord {
    name: DomainName,
    ttl: u32,
    rclass: RecordClass,
    authority: HostName,
}

impl NsRecord {
    /// Constructs a new NS record
    pub fn new(name: DomainName, ttl: u32, rclass: RecordClass, authority: HostName) -> Self {
        Self {
            name,
            ttl,
            rclass,
            authority,
        }
    }

    /// A name to which authority has been delegated to for this name and class
    pub fn authority(&self) -> &HostName {
        &self.authority
    }
}

impl<'read> RecordData<'read> for NsRecord {
    fn data_size(&self) -> usize {
        self.authority.size()
    }

    fn encode_data(&self, writer: &mut WireWrite) -> Result<(), WireError> {
        self.authority.encode(writer)
    }

    fn decode_data(
        name: DomainName,
        ttl: u32,
        rclass: RecordClass,
        rtype: RecordType,
        len: u16,
        reader: &mut WireRead<'read>,
    ) -> Result<Self, WireError> {
        debug_assert_eq!(rtype, RecordType::Ns);

        let authority = HostName::decode(reader)?;

        if authority.size() != len as usize {
            return Err(WireError::InvalidLength {
                expected: authority.size(),
                actual: len as usize,
            });
        }

        Ok(Self {
            name,
            ttl,
            rclass,
            authority,
        })
    }

    fn decode_zone(
        name: DomainName,
        ttl: u32,
        rclass: RecordClass,
        rtype: RecordType,
        reader: &mut ZoneReader,
    ) -> Result<Self, ZoneError> {
        debug_assert_eq!(rtype, RecordType::Ns);

        let authority = reader.read_name()?.into();

        Ok(Self {
            name,
            ttl,
            rclass,
            authority,
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
        RecordType::Ns
    }

    fn additionals(&self, _: &Question) -> Vec<(Question, ResolveType)> {
        vec![
            (
                Question::new(self.authority.clone().into(), self.rclass, RecordType::A),
                ResolveType::Additional,
            ),
            (
                Question::new(self.authority.clone().into(), self.rclass, RecordType::Aaaa),
                ResolveType::Additional,
            ),
        ]
    }
}

impl Display for NsRecord {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}", self.authority)
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
        let record = Record::Ns(NsRecord::new(
            "example.com.".parse().unwrap(),
            86400,
            RecordClass::In,
            "ns2.example.com.".parse().unwrap(),
        ));

        let wire = to_wire(&record).unwrap();
        assert_debug_snapshot!(wire);

        assert_eq!(from_wire::<Record>(&wire), Ok(record));
    }

    #[test]
    fn zone() {
        let record = Record::Ns(NsRecord::new(
            "example.com.".parse().unwrap(),
            86400,
            RecordClass::In,
            "ns1.example.com.".parse().unwrap(),
        ));

        assert_display_snapshot!(record);

        let mut root = Node::new();
        root.insert(Label::from(b"com".to_vec()))
            .insert(Label::from(b"example".to_vec()))
            .add_record(record.clone());

        assert_eq!(read_zone(&record.to_string(), Vec::new().into()), Ok(root));
    }
}
