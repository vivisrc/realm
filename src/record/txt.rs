use std::fmt::{self, Display, Formatter};

use crate::{
    record::{RecordClass, RecordData, RecordType},
    text::{DomainName, Text},
    wire::{WireDecode, WireEncode, WireError, WireRead, WireWrite},
    zone::{ZoneError, ZoneErrorKind, ZoneReader},
};

/// A TXT record
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxtRecord {
    name: DomainName,
    ttl: u32,
    rclass: RecordClass,
    strings: Vec<Text>,
}

impl TxtRecord {
    /// Constructs a new TXT record
    pub fn new(name: DomainName, ttl: u32, rclass: RecordClass, strings: &[Text]) -> Self {
        Self {
            name,
            ttl,
            rclass,
            strings: strings.to_vec(),
        }
    }

    /// Constructs a new TXT record with only one string
    pub fn single(name: DomainName, ttl: u32, class: RecordClass, string: Text) -> Self {
        Self::new(name, ttl, class, &[string])
    }

    /// One or more strings
    pub fn strings(&self) -> &[Text] {
        &self.strings
    }
}

impl<'read> RecordData<'read> for TxtRecord {
    fn data_size(&self) -> usize {
        self.strings.iter().map(|string| string.size()).sum()
    }

    fn encode_data(&self, writer: &mut WireWrite) -> Result<(), WireError> {
        for string in &self.strings {
            string.encode(writer)?;
        }
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
        debug_assert_eq!(rtype, RecordType::Txt);

        let mut strings = Vec::new();

        let mut expected = len as isize;
        loop {
            if expected == 0 {
                break;
            }

            if expected < 0 {
                return Err(WireError::InvalidLength {
                    expected: (len as isize - expected) as usize,
                    actual: len as usize,
                });
            }

            let string = Text::decode(reader)?;
            expected -= string.size() as isize;
            strings.push(string);
        }

        Ok(Self {
            name,
            ttl,
            rclass,
            strings,
        })
    }

    fn decode_zone(
        name: DomainName,
        ttl: u32,
        rclass: RecordClass,
        rtype: RecordType,
        reader: &mut ZoneReader,
    ) -> Result<Self, ZoneError> {
        debug_assert_eq!(rtype, RecordType::Txt);

        let mut strings = vec![reader.read_text()?];

        loop {
            match reader.read_blank() {
                Ok(_) => match reader.peek() {
                    Some(_) => strings.push(reader.read_text()?),
                    None => break,
                },
                Err(err) => match err.kind() {
                    ZoneErrorKind::IncompleteEntry => break,
                    _ => return Err(err),
                },
            }
        }

        strings.shrink_to_fit();

        Ok(Self {
            name,
            ttl,
            rclass,
            strings,
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
        RecordType::Txt
    }
}

impl Display for TxtRecord {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            self.strings
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(" "),
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
        let record = Record::Txt(TxtRecord::new(
            "15.example.com.".parse().unwrap(),
            7200,
            RecordClass::In,
            &[r#""fizz""#.parse().unwrap(), r#""buzz""#.parse().unwrap()],
        ));

        let wire = to_wire(&record).unwrap();
        assert_debug_snapshot!(wire);

        assert_eq!(from_wire::<Record>(&wire), Ok(record));
    }

    #[test]
    fn zone() {
        let record = Record::Txt(TxtRecord::new(
            "example.com.".parse().unwrap(),
            7200,
            RecordClass::In,
            &[
                r#""v=DKIM1; p=""#.parse().unwrap(),
                r#""VeryLongPublicKeyHere""#.parse().unwrap(),
            ],
        ));

        assert_display_snapshot!(record);

        let mut root = Node::new();
        root.insert(Label::from(b"com".to_vec()))
            .insert(Label::from(b"example".to_vec()))
            .add_record(record.clone());

        assert_eq!(read_zone(&record.to_string(), Vec::new().into()), Ok(root));
    }
}
