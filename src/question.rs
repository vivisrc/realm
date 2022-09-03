use std::fmt::{self, Display, Formatter};

use crate::{
    record::{RecordClass, RecordType},
    text::DomainName,
    wire::{WireDecode, WireEncode, WireError, WireRead, WireWrite},
};

/// A DNS question
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Question {
    name: DomainName,
    qclass: RecordClass,
    qtype: RecordType,
}

impl Question {
    pub fn new(name: DomainName, qclass: RecordClass, qtype: RecordType) -> Self {
        Self {
            name,
            qclass,
            qtype,
        }
    }

    /// The name of this question
    pub fn name(&self) -> &DomainName {
        &self.name
    }

    /// The class of this question
    pub fn qclass(&self) -> RecordClass {
        self.qclass
    }

    /// The type of this question
    pub fn qtype(&self) -> RecordType {
        self.qtype
    }
}

impl WireEncode for Question {
    fn size(&self) -> usize {
        self.name.size() + 4
    }

    fn encode(&self, writer: &mut WireWrite) -> Result<(), WireError> {
        self.name.encode(writer)?;
        u16::from(self.qtype).encode(writer)?;
        u16::from(self.qclass).encode(writer)?;
        Ok(())
    }
}

impl<'read> WireDecode<'read> for Question {
    fn decode(reader: &mut WireRead<'read>) -> Result<Self, WireError> {
        let name = DomainName::decode(reader)?;
        let query_type = u16::decode(reader)?.into();
        let query_class = u16::decode(reader)?.into();

        Ok(Self {
            name,
            qtype: query_type,
            qclass: query_class,
        })
    }
}

impl Display for Question {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}\t{}\t{}", self.name, self.qclass, self.qtype,)
    }
}
