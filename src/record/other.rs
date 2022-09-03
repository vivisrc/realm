use std::fmt::{self, Display, Formatter};

use crate::{
    record::{RecordClass, RecordData, RecordType},
    text::DomainName,
    wire::{WireError, WireRead, WireWrite},
    zone::{ZoneError, ZoneErrorKind, ZoneReader},
};

/// Represents an arbitrary DNS record
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OtherRecord {
    name: DomainName,
    ttl: u32,
    rtype: RecordType,
    rclass: RecordClass,
    data: Vec<u8>,
}

impl OtherRecord {
    /// Constructs a new arbitrary DNS record
    pub fn new(
        name: DomainName,
        ttl: u32,
        rtype: RecordType,
        rclass: RecordClass,
        data: &[u8],
    ) -> Self {
        assert!(
            data.len() <= u16::MAX as usize,
            "DNS record size be greater than u16::MAX"
        );

        Self {
            name,
            ttl,
            rclass,
            rtype,
            data: data.to_vec(),
        }
    }

    /// The binary data of the record
    pub fn data(&self) -> &[u8] {
        &self.data
    }
}

impl<'read> RecordData<'read> for OtherRecord {
    fn data_size(&self) -> usize {
        self.data.len()
    }

    fn encode_data(&self, writer: &mut WireWrite) -> Result<(), WireError> {
        writer.write(&self.data)
    }

    fn decode_data(
        name: DomainName,
        ttl: u32,
        rclass: RecordClass,
        rtype: RecordType,
        len: u16,
        reader: &mut WireRead<'read>,
    ) -> Result<Self, WireError> {
        let mut data = vec![0; len as usize];
        reader.read(&mut data)?;

        Ok(Self {
            name,
            rclass,
            rtype,
            ttl,
            data,
        })
    }

    fn decode_zone(
        _: DomainName,
        _: u32,
        _: RecordClass,
        _: RecordType,
        reader: &mut ZoneReader,
    ) -> Result<Self, ZoneError> {
        reader.error(ZoneErrorKind::BadEntry)
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
        self.rtype
    }
}

impl Display for OtherRecord {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "\\# {} ", self.data_size())?;
        for byte in &self.data {
            write!(f, "{:0>2x}", byte)?;
        }
        Ok(())
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
        let record = Record::Other(OtherRecord::new(
            "facade.example.com.".parse().unwrap(),
            7200,
            RecordType::Other(0xff00),
            RecordClass::In,
            &[0xfa, 0xca, 0xde],
        ));

        let wire = to_wire(&record).unwrap();
        assert_debug_snapshot!(wire);

        assert_eq!(from_wire::<Record>(&wire), Ok(record));
    }

    #[test]
    fn zone() {
        let record = Record::Other(OtherRecord::new(
            "deadbeef.example.com.".parse().unwrap(),
            300,
            RecordType::Other(0xff00),
            RecordClass::In,
            &[0xde, 0xad, 0xbe, 0xef],
        ));

        assert_display_snapshot!(record);

        let mut root = Node::new();
        root.insert(Label::from(b"com".to_vec()))
            .insert(Label::from(b"example".to_vec()))
            .insert(Label::from(b"deadbeef".to_vec()))
            .add_record(record.clone());

        assert_eq!(read_zone(&record.to_string(), Vec::new().into()), Ok(root));
    }

    #[test]
    fn zone_zero_length() {
        assert_debug_snapshot!(read_zone(". 3600 IN TYPE65280 \\# 0", Vec::new().into()))
    }

    #[test]
    fn zone_blanks() {
        assert_debug_snapshot!(read_zone(
            ". 3600 IN TYPE65280 \\# 4 00 (\n11\n22 ) 33",
            Vec::new().into(),
        ))
    }
}
