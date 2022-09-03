use std::fmt::{self, Display, Formatter};

use crate::{
    question::Question,
    record::{RecordClass, RecordData, RecordType},
    resolver::ResolveType,
    text::{DomainName, HostName},
    wire::{WireDecode, WireEncode, WireError, WireRead, WireWrite},
    zone::{ZoneError, ZoneReader},
};

/// A CNAME record
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CnameRecord {
    name: DomainName,
    ttl: u32,
    rclass: RecordClass,
    canonical: HostName,
}

impl CnameRecord {
    /// Constructs a new CNAME record
    pub fn new(name: DomainName, ttl: u32, rclass: RecordClass, canonical: HostName) -> Self {
        Self {
            name,
            ttl,
            rclass,
            canonical,
        }
    }

    /// The canonical or primary name
    pub fn canonical(&self) -> &HostName {
        &self.canonical
    }
}

impl<'read> RecordData<'read> for CnameRecord {
    fn data_size(&self) -> usize {
        self.canonical.size()
    }

    fn encode_data(&self, writer: &mut WireWrite) -> Result<(), WireError> {
        self.canonical.encode(writer)
    }

    fn decode_data(
        name: DomainName,
        ttl: u32,
        rclass: RecordClass,
        rtype: RecordType,
        len: u16,
        reader: &mut WireRead<'read>,
    ) -> Result<Self, WireError> {
        debug_assert_eq!(rtype, RecordType::Cname);

        let canonical = HostName::decode(reader)?;

        if canonical.size() != len as usize {
            return Err(WireError::InvalidLength {
                expected: canonical.size(),
                actual: len as usize,
            });
        }

        Ok(Self {
            name,
            ttl,
            rclass,
            canonical,
        })
    }

    fn decode_zone(
        name: DomainName,
        ttl: u32,
        rclass: RecordClass,
        rtype: RecordType,
        reader: &mut ZoneReader,
    ) -> Result<Self, ZoneError> {
        debug_assert_eq!(rtype, RecordType::Cname);

        let canonical = reader.read_name()?.into();

        Ok(Self {
            name,
            ttl,
            rclass,
            canonical,
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
        RecordType::Cname
    }

    fn additionals(&self, question: &Question) -> Vec<(Question, ResolveType)> {
        if question.qtype() == RecordType::Cname {
            return Vec::new();
        }

        vec![(
            Question::new(
                self.canonical().clone().into(),
                self.rclass,
                question.qtype(),
            ),
            ResolveType::Alias,
        )]
    }
}

impl Display for CnameRecord {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}", self.canonical)
    }
}

#[cfg(test)]
mod tests {
    use insta::{assert_debug_snapshot, assert_display_snapshot};

    use super::*;
    use crate::{node::Node, record::Record, text::Label, wire::to_wire, zone::read_zone};

    #[test]
    fn wire() {
        let record = Record::Cname(CnameRecord::new(
            "mail.example.com.".parse().unwrap(),
            7200,
            RecordClass::In,
            "alpha.host.example.com.".parse().unwrap(),
        ));

        let wire = to_wire(&record);
        assert_debug_snapshot!(wire);
    }

    #[test]
    fn zone() {
        let record = Record::Cname(CnameRecord::new(
            "www.example.com.".parse().unwrap(),
            7200,
            RecordClass::In,
            "gamma.host.example.com.".parse().unwrap(),
        ));

        assert_display_snapshot!(record);

        let mut root = Node::new();
        root.insert(Label::from(b"com".to_vec()))
            .insert(Label::from(b"example".to_vec()))
            .insert(Label::from(b"www".to_vec()))
            .add_record(record.clone());

        assert_eq!(read_zone(&record.to_string(), Vec::new().into()), Ok(root));
    }
}
