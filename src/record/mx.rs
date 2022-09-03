use std::fmt::{self, Display, Formatter};

use crate::{
    question::Question,
    record::{RecordClass, RecordData, RecordType},
    resolver::ResolveType,
    text::{DomainName, HostName},
    wire::{WireDecode, WireEncode, WireError, WireRead, WireWrite},
    zone::{ZoneError, ZoneReader},
};

/// An MX record
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MxRecord {
    name: DomainName,
    ttl: u32,
    rclass: RecordClass,
    priority: u16,
    exchange: HostName,
}

impl MxRecord {
    /// Constructs a new MX record
    pub fn new(
        name: DomainName,
        ttl: u32,
        rclass: RecordClass,
        priority: u16,
        exchange: HostName,
    ) -> Self {
        Self {
            name,
            ttl,
            rclass,
            priority,
            exchange,
        }
    }

    /// The priority of the exchange
    pub fn priority(&self) -> u16 {
        self.priority
    }

    /// The host of this mail exchange
    pub fn exchange(&self) -> &HostName {
        &self.exchange
    }
}

impl<'read> RecordData<'read> for MxRecord {
    fn data_size(&self) -> usize {
        self.exchange.size() + 2
    }

    fn encode_data(&self, writer: &mut WireWrite) -> Result<(), WireError> {
        self.priority.encode(writer)?;
        self.exchange.encode(writer)?;

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
        debug_assert_eq!(rtype, RecordType::Mx);

        let priority = u16::decode(reader)?;
        let exchange = HostName::decode(reader)?;

        if exchange.size() + 2 != len as usize {
            return Err(WireError::InvalidLength {
                expected: exchange.size(),
                actual: len as usize,
            });
        }

        Ok(Self {
            name,
            ttl,
            rclass,
            priority,
            exchange,
        })
    }

    fn decode_zone(
        name: DomainName,
        ttl: u32,
        rclass: RecordClass,
        rtype: RecordType,
        reader: &mut ZoneReader,
    ) -> Result<Self, ZoneError> {
        debug_assert_eq!(rtype, RecordType::Mx);

        let priority = reader.read_parsable()?;
        reader.read_blank()?;
        let exchange = reader.read_name()?.into();

        Ok(Self {
            name,
            ttl,
            rclass,
            priority,
            exchange,
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
        RecordType::Mx
    }

    fn additionals(&self, _: &Question) -> Vec<(Question, ResolveType)> {
        vec![
            (
                Question::new(self.exchange.clone().into(), self.rclass, RecordType::A),
                ResolveType::Additional,
            ),
            (
                Question::new(self.exchange.clone().into(), self.rclass, RecordType::Aaaa),
                ResolveType::Additional,
            ),
        ]
    }
}

impl Display for MxRecord {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{} {}", self.priority, self.exchange)
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
        let record = Record::Mx(MxRecord::new(
            "mail.example.com.".parse().unwrap(),
            7200,
            RecordClass::In,
            20,
            "lambda.host.example.com.".parse().unwrap(),
        ));

        let wire = to_wire(&record).unwrap();
        assert_debug_snapshot!(wire);

        assert_eq!(from_wire::<Record>(&wire), Ok(record));
    }

    #[test]
    fn zone() {
        let record = Record::Mx(MxRecord::new(
            "example.com.".parse().unwrap(),
            7200,
            RecordClass::In,
            10,
            "alpha.host.example.com.".parse().unwrap(),
        ));

        assert_display_snapshot!(record);

        let mut root = Node::new();
        root.insert(Label::from(b"com".to_vec()))
            .insert(Label::from(b"example".to_vec()))
            .add_record(record.clone());

        assert_eq!(read_zone(&record.to_string(), Vec::new().into()), Ok(root));
    }
}
