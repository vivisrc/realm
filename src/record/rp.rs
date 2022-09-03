use std::fmt::{self, Display, Formatter};

use crate::{
    record::{RecordClass, RecordData, RecordType},
    text::{DomainName, HostName},
    wire::{WireDecode, WireEncode, WireError, WireRead, WireWrite},
    zone::{ZoneError, ZoneReader},
};

/// A RP record
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpRecord {
    name: DomainName,
    ttl: u32,
    rclass: RecordClass,
    mailbox: HostName,
    text: HostName,
}

impl RpRecord {
    /// Constructs a new RP record
    pub fn new(
        name: DomainName,
        ttl: u32,
        rclass: RecordClass,
        mailbox: HostName,
        text: HostName,
    ) -> Self {
        Self {
            name,
            ttl,
            rclass,
            mailbox,
            text,
        }
    }

    /// The mailbox of the responsible person
    pub fn mailbox(&self) -> &HostName {
        &self.mailbox
    }

    /// The domain name that hosts TXT records for additional info
    pub fn text(&self) -> &HostName {
        &self.text
    }
}

impl<'read> RecordData<'read> for RpRecord {
    fn data_size(&self) -> usize {
        self.mailbox.size() + self.text.size()
    }

    fn encode_data(&self, writer: &mut WireWrite) -> Result<(), WireError> {
        self.mailbox.encode(writer)?;
        self.text.encode(writer)?;

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
        debug_assert_eq!(rtype, RecordType::Rp);

        let mailbox = HostName::decode(reader)?;
        let text = HostName::decode(reader)?;

        if mailbox.size() + text.size() != len as usize {
            return Err(WireError::InvalidLength {
                expected: mailbox.size() + text.size(),
                actual: len as usize,
            });
        }

        Ok(Self {
            name,
            ttl,
            rclass,
            mailbox,
            text,
        })
    }

    fn decode_zone(
        name: DomainName,
        ttl: u32,
        rclass: RecordClass,
        rtype: RecordType,
        reader: &mut ZoneReader,
    ) -> Result<Self, ZoneError> {
        debug_assert_eq!(rtype, RecordType::Rp);

        let mailbox = reader.read_name()?.into();
        reader.read_blank()?;
        let text = reader.read_name()?.into();

        Ok(Self {
            name,
            ttl,
            rclass,
            mailbox,
            text,
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
        RecordType::Rp
    }
}

impl Display for RpRecord {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{} {}", self.mailbox, self.text)
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
        let record = Record::Rp(RpRecord::new(
            "example.com.".parse().unwrap(),
            86400,
            RecordClass::In,
            "root.example.com.".parse().unwrap(),
            "root.people.example.com.".parse().unwrap(),
        ));

        let wire = to_wire(&record).unwrap();
        assert_debug_snapshot!(wire);

        assert_eq!(from_wire::<Record>(&wire), Ok(record));
    }

    #[test]
    fn zone() {
        let record = Record::Rp(RpRecord::new(
            "example.com.".parse().unwrap(),
            86400,
            RecordClass::In,
            "admin.example.com.".parse().unwrap(),
            "admin.people.example.com.".parse().unwrap(),
        ));

        assert_display_snapshot!(record);

        let mut root = Node::new();
        root.insert(Label::from(b"com".to_vec()))
            .insert(Label::from(b"example".to_vec()))
            .add_record(record.clone());

        assert_eq!(read_zone(&record.to_string(), Vec::new().into()), Ok(root));
    }
}
