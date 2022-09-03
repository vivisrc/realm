use std::fmt::{self, Display, Formatter};

use crate::{
    question::Question,
    record::{RecordClass, RecordData, RecordType},
    resolver::ResolveType,
    text::{DomainName, HostName},
    wire::{WireDecode, WireEncode, WireError, WireRead, WireWrite},
    zone::{ZoneError, ZoneReader},
};

/// An SRV record
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SrvRecord {
    name: DomainName,
    ttl: u32,
    rclass: RecordClass,
    priority: u16,
    weight: u16,
    port: u16,
    target: HostName,
}

impl SrvRecord {
    /// Constructs a new SRV record
    pub fn new(
        name: DomainName,
        ttl: u32,
        rclass: RecordClass,
        priority: u16,
        weight: u16,
        port: u16,
        target: HostName,
    ) -> Self {
        Self {
            name,
            ttl,
            rclass,
            priority,
            weight,
            port,
            target,
        }
    }

    /// The priority of the service
    pub fn priority(&self) -> u16 {
        self.priority
    }

    /// The weight of the service
    pub fn weight(&self) -> u16 {
        self.weight
    }

    /// The port of the service
    pub fn port(&self) -> u16 {
        self.port
    }

    /// The target of the service
    pub fn target(&self) -> &HostName {
        &self.target
    }
}

impl<'read> RecordData<'read> for SrvRecord {
    fn data_size(&self) -> usize {
        self.target.size() + 6
    }

    fn encode_data(&self, writer: &mut WireWrite) -> Result<(), WireError> {
        self.priority.encode(writer)?;
        self.weight.encode(writer)?;
        self.port.encode(writer)?;
        self.target.encode(writer)?;

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
        debug_assert_eq!(rtype, RecordType::Srv);

        let priority = u16::decode(reader)?;
        let weight = u16::decode(reader)?;
        let port = u16::decode(reader)?;
        let target = HostName::decode(reader)?;

        if target.size() + 6 != len as usize {
            return Err(WireError::InvalidLength {
                expected: target.size(),
                actual: len as usize,
            });
        }

        Ok(Self {
            name,
            ttl,
            rclass,
            priority,
            weight,
            port,
            target,
        })
    }

    fn decode_zone(
        name: DomainName,
        ttl: u32,
        rclass: RecordClass,
        rtype: RecordType,
        reader: &mut ZoneReader,
    ) -> Result<Self, ZoneError> {
        debug_assert_eq!(rtype, RecordType::Srv);

        let priority = reader.read_parsable()?;
        reader.read_blank()?;
        let weight = reader.read_parsable()?;
        reader.read_blank()?;
        let port = reader.read_parsable()?;
        reader.read_blank()?;
        let target = reader.read_name()?.into();

        Ok(Self {
            name,
            ttl,
            rclass,
            priority,
            weight,
            port,
            target,
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
        RecordType::Srv
    }

    fn additionals(&self, _: &Question) -> Vec<(Question, ResolveType)> {
        vec![
            (
                Question::new(self.target.clone().into(), self.rclass, RecordType::A),
                ResolveType::Additional,
            ),
            (
                Question::new(self.target.clone().into(), self.rclass, RecordType::Aaaa),
                ResolveType::Additional,
            ),
        ]
    }
}

impl Display for SrvRecord {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(
            f,
            "{} {} {} {}",
            self.priority, self.weight, self.port, self.target,
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
        let record = Record::Srv(SrvRecord::new(
            "_imaps._tcp.example.com.".parse().unwrap(),
            3600,
            RecordClass::In,
            10,
            10,
            993,
            "imap.example.com.".parse().unwrap(),
        ));

        let wire = to_wire(&record).unwrap();
        assert_debug_snapshot!(wire);

        assert_eq!(from_wire::<Record>(&wire), Ok(record));
    }

    #[test]
    fn zone() {
        let record = Record::Srv(SrvRecord::new(
            "_submissions._tcp.example.com.".parse().unwrap(),
            3600,
            RecordClass::In,
            10,
            10,
            587,
            "smtp.example.com.".parse().unwrap(),
        ));

        assert_display_snapshot!(record);

        let mut root = Node::new();
        root.insert(Label::from(b"com".to_vec()))
            .insert(Label::from(b"example".to_vec()))
            .insert(Label::from(b"_tcp".to_vec()))
            .insert(Label::from(b"_submissions".to_vec()))
            .add_record(record.clone());

        assert_eq!(read_zone(&record.to_string(), Vec::new().into()), Ok(root));
    }
}
