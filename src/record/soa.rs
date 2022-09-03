use std::fmt::{self, Display, Formatter};

use crate::{
    record::{RecordClass, RecordData, RecordType},
    serial::Serial,
    text::{DomainName, HostName},
    wire::{WireDecode, WireEncode, WireError, WireRead, WireWrite},
    zone::{ZoneError, ZoneReader},
};

/// A SOA record
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SoaRecord {
    name: DomainName,
    ttl: u32,
    rclass: RecordClass,
    primary: HostName,
    admin: HostName,
    serial: Serial,
    refresh: u32,
    retry: u32,
    expire: u32,
    minimum: u32,
}

impl SoaRecord {
    /// Constructs a new SOA record
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        name: DomainName,
        ttl: u32,
        rclass: RecordClass,
        primary: HostName,
        admin: HostName,
        serial: Serial,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
    ) -> Self {
        Self {
            name,
            ttl,
            rclass,
            primary,
            admin,
            serial,
            refresh,
            retry,
            expire,
            minimum,
        }
    }

    /// The domain name of the primary name server
    pub fn primary(&self) -> &HostName {
        &self.primary
    }

    /// The domain name specifying the mailbox of the authority's admin
    pub fn admin(&self) -> &HostName {
        &self.admin
    }

    /// The serial number of this authority
    pub fn serial(&self) -> Serial {
        self.serial
    }

    /// The time interval in seconds to refresh the authority
    pub fn refresh(&self) -> u32 {
        self.refresh
    }

    /// The time interval in seconds to retry after a failed refresh
    pub fn retry(&self) -> u32 {
        self.retry
    }

    /// The upper bound of time in seconds of how long a stale server can remain authoritative
    pub fn expire(&self) -> u32 {
        self.expire
    }

    /// The time in seconds that negative responses should be cached for
    pub fn minimum(&self) -> u32 {
        self.minimum
    }
}

impl<'read> RecordData<'read> for SoaRecord {
    fn data_size(&self) -> usize {
        self.primary.size() + self.admin.size() + 20
    }

    fn encode_data(&self, writer: &mut WireWrite) -> Result<(), WireError> {
        self.primary.encode(writer)?;
        self.admin.encode(writer)?;
        u32::from(self.serial).encode(writer)?;
        self.refresh.encode(writer)?;
        self.retry.encode(writer)?;
        self.expire.encode(writer)?;
        self.minimum.encode(writer)?;

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
        debug_assert_eq!(rtype, RecordType::Soa);

        let primary = HostName::decode(reader)?;
        let admin = HostName::decode(reader)?;

        if primary.size() + admin.size() + 20 != len as usize {
            return Err(WireError::InvalidLength {
                expected: primary.size() + admin.size() + 20,
                actual: len as usize,
            });
        }

        let serial = u32::decode(reader)?.into();
        let refresh = u32::decode(reader)?;
        let retry = u32::decode(reader)?;
        let expire = u32::decode(reader)?;
        let minimum = u32::decode(reader)?;

        Ok(Self {
            name,
            ttl,
            rclass,
            primary,
            admin,
            serial,
            refresh,
            retry,
            expire,
            minimum,
        })
    }

    fn decode_zone(
        name: DomainName,
        ttl: u32,
        rclass: RecordClass,
        rtype: RecordType,
        reader: &mut ZoneReader,
    ) -> Result<Self, ZoneError> {
        debug_assert_eq!(rtype, RecordType::Soa);

        let primary = reader.read_name()?.into();
        reader.read_blank()?;
        let admin = reader.read_name()?.into();
        reader.read_blank()?;
        let serial = reader.read_parsable::<u32>()?.into();
        reader.read_blank()?;
        let refresh = reader.read_parsable()?;
        reader.read_blank()?;
        let retry = reader.read_parsable()?;
        reader.read_blank()?;
        let expire = reader.read_parsable()?;
        reader.read_blank()?;
        let minimum = reader.read_parsable()?;

        Ok(Self {
            name,
            ttl,
            rclass,
            primary,
            admin,
            serial,
            refresh,
            retry,
            expire,
            minimum,
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
        RecordType::Soa
    }
}

impl Display for SoaRecord {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(
            f,
            "{} {} {} {} {} {} {}",
            self.primary,
            self.admin,
            u32::from(self.serial),
            self.refresh,
            self.retry,
            self.expire,
            self.minimum,
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
        let record = Record::Soa(SoaRecord::new(
            "host.example.com.".parse().unwrap(),
            300,
            RecordClass::In,
            "dyn.example.com.".parse().unwrap(),
            "admin.example.com.".parse().unwrap(),
            Serial::from(2022010101),
            3600,
            1800,
            86400,
            300,
        ));

        let wire = to_wire(&record).unwrap();
        assert_debug_snapshot!(wire);

        assert_eq!(from_wire::<Record>(&wire), Ok(record));
    }

    #[test]
    fn zone() {
        let record = Record::Soa(SoaRecord::new(
            "example.com.".parse().unwrap(),
            300,
            RecordClass::In,
            "ns1.example.com.".parse().unwrap(),
            "admin.example.com.".parse().unwrap(),
            Serial::from(400),
            3600,
            1800,
            86400,
            300,
        ));

        assert_display_snapshot!(record);

        let mut root = Node::new();
        root.insert(Label::from(b"com".to_vec()))
            .insert(Label::from(b"example".to_vec()))
            .add_record(record.clone());

        assert_eq!(read_zone(&record.to_string(), Vec::new().into()), Ok(root));
    }
}
