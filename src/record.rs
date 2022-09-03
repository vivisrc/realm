use std::{
    error::Error,
    fmt::{self, Display, Formatter},
    str::FromStr,
};

use enum_other::other;
use paste::paste;

use crate::{
    question::Question,
    record::{
        ch_a::ChARecord, cname::CnameRecord, hinfo::HinfoRecord, in_a::InARecord,
        in_aaaa::InAaaaRecord, loc::LocRecord, mx::MxRecord, ns::NsRecord, opt::OptRecord,
        other::OtherRecord, ptr::PtrRecord, rp::RpRecord, soa::SoaRecord, srv::SrvRecord,
        txt::TxtRecord,
    },
    resolver::ResolveType,
    text::DomainName,
    wire::{WireDecode, WireEncode, WireError, WireRead, WireWrite},
    zone::{ZoneError, ZoneReader},
};

pub mod ch_a;
pub mod cname;
pub mod hinfo;
pub mod in_a;
pub mod in_aaaa;
pub mod loc;
pub mod mx;
pub mod ns;
pub mod opt;
pub mod other;
pub mod ptr;
pub mod rp;
pub mod soa;
pub mod srv;
pub mod txt;

/// A record or question class
#[other(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecordClass {
    In = 1,
    Ch = 3,
    None = 254,
    Any = 255,
}

impl Display for RecordClass {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Self::In => write!(f, "IN"),
            Self::Ch => write!(f, "CH"),
            Self::None => write!(f, "NONE"),
            Self::Any => write!(f, "ANY"),
            Self::Other(rclass) => write!(f, "CLASS{}", rclass),
        }
    }
}

#[derive(Debug)]
pub struct ParseRecordClassError;

impl Display for ParseRecordClassError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "provided string was not a recognised record class")
    }
}

impl Error for ParseRecordClassError {}

impl FromStr for RecordClass {
    type Err = ParseRecordClassError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.starts_with("CLASS") {
            match s.get("CLASS".len()..) {
                Some(digits) => {
                    if let Ok(rclass) = digits.parse::<u16>() {
                        return Ok(Self::from(rclass));
                    }
                }
                None => (),
            }
        }

        match s {
            "IN" => Ok(Self::In),
            "CH" => Ok(Self::Ch),
            "NONE" => Ok(Self::None),
            "ANY" => Ok(Self::Any),
            _ => Err(ParseRecordClassError),
        }
    }
}

/// A record or question type
#[other(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecordType {
    A = 1,
    Ns = 2,
    Cname = 5,
    Soa = 6,
    Ptr = 12,
    Hinfo = 13,
    Mx = 15,
    Txt = 16,
    Rp = 17,
    Aaaa = 28,
    Loc = 29,
    Srv = 33,
    Opt = 41,
}

impl Display for RecordType {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Self::A => write!(f, "A"),
            Self::Ns => write!(f, "NS"),
            Self::Cname => write!(f, "CNAME"),
            Self::Soa => write!(f, "SOA"),
            Self::Ptr => write!(f, "PTR"),
            Self::Hinfo => write!(f, "HINFO"),
            Self::Mx => write!(f, "MX"),
            Self::Txt => write!(f, "TXT"),
            Self::Rp => write!(f, "RP"),
            Self::Aaaa => write!(f, "AAAA"),
            Self::Loc => write!(f, "LOC"),
            Self::Srv => write!(f, "SRV"),
            Self::Opt => write!(f, "OPT"),
            Self::Other(rtype) => write!(f, "TYPE{}", rtype),
        }
    }
}

#[derive(Debug)]
pub struct ParseRecordTypeError;

impl Display for ParseRecordTypeError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "provided string was not a recognised record class")
    }
}

impl Error for ParseRecordTypeError {}

impl FromStr for RecordType {
    type Err = ParseRecordTypeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.starts_with("TYPE") {
            match s.get("TYPE".len()..) {
                Some(digits) => {
                    if let Ok(rtype) = digits.parse::<u16>() {
                        return Ok(Self::from(rtype));
                    }
                }
                None => (),
            }
        }

        match s {
            "A" => Ok(Self::A),
            "NS" => Ok(Self::Ns),
            "CNAME" => Ok(Self::Cname),
            "SOA" => Ok(Self::Soa),
            "PTR" => Ok(Self::Ptr),
            "HINFO" => Ok(Self::Hinfo),
            "MX" => Ok(Self::Mx),
            "TXT" => Ok(Self::Txt),
            "RP" => Ok(Self::Rp),
            "AAAA" => Ok(Self::Aaaa),
            "LOC" => Ok(Self::Loc),
            "SRV" => Ok(Self::Srv),
            "OPT" => Ok(Self::Opt),
            _ => Err(ParseRecordTypeError),
        }
    }
}

/// A DNS record
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Record {
    InA(InARecord),
    ChA(ChARecord),
    Ns(NsRecord),
    Cname(CnameRecord),
    Soa(SoaRecord),
    Ptr(PtrRecord),
    Hinfo(HinfoRecord),
    Mx(MxRecord),
    Txt(TxtRecord),
    Rp(RpRecord),
    InAaaa(InAaaaRecord),
    Loc(LocRecord),
    Srv(SrvRecord),
    Opt(OptRecord),
    Other(OtherRecord),
}

impl WireEncode for Record {
    fn size(&self) -> usize {
        10 + self.name().size() + self.data_size()
    }

    fn encode(&self, writer: &mut WireWrite) -> Result<(), WireError> {
        self.name().encode(writer)?;
        u16::from(self.rtype()).encode(writer)?;
        u16::from(self.rclass()).encode(writer)?;
        self.ttl().encode(writer)?;
        (self.data_size() as u16).encode(writer)?;

        self.encode_data(writer)?;

        Ok(())
    }
}

impl<'read> WireDecode<'read> for Record {
    fn decode(reader: &mut WireRead<'read>) -> Result<Self, WireError> {
        let name = DomainName::decode(reader)?;
        let rtype = u16::decode(reader)?.into();
        let rclass = u16::decode(reader)?.into();
        let ttl = u32::decode(reader)?;
        let len = u16::decode(reader)?;

        let data = Self::decode_data(name, ttl, rclass, rtype, len, reader)?;

        Ok(data)
    }
}

/// A trait containing common methods to be used in various DNS related operations
pub trait RecordData<'read>: Sized {
    /// The size of this record's data
    fn data_size(&self) -> usize;

    /// Encodes this record's data into the given writer
    fn encode_data(&self, writer: &mut WireWrite) -> Result<(), WireError>;

    /// Decodes data from a given reader into a record
    fn decode_data(
        name: DomainName,
        ttl: u32,
        rclass: RecordClass,
        rtype: RecordType,
        len: u16,
        reader: &mut WireRead<'read>,
    ) -> Result<Self, WireError>;

    /// Decodes zone tokens into a record
    fn decode_zone(
        name: DomainName,
        ttl: u32,
        rclass: RecordClass,
        rtype: RecordType,
        reader: &mut ZoneReader,
    ) -> Result<Self, ZoneError>;

    /// The domain name of this record
    fn name(&self) -> &DomainName;

    /// The time to lease for this record
    fn ttl(&self) -> u32;

    /// The record class of this record
    fn rclass(&self) -> RecordClass;

    /// The record type of this record
    fn rtype(&self) -> RecordType;

    /// Gets additional records that should be resolved when given as an answer
    fn additionals(&self, _: &Question) -> Vec<(Question, ResolveType)> {
        Vec::new()
    }
}

macro_rules! dns_record_impl {
    ($(($rclass:tt, $rtype:tt),)*) => {
        impl<'read> RecordData<'read> for Record {
            fn data_size(&self) -> usize {
                match self {
                    $(dns_record_impl!(@ variant($rclass, $rtype, data)) => data.data_size()),*
                }
            }

            fn encode_data(&self, writer: &mut WireWrite) -> Result<(), WireError> {
                match self {
                    $(dns_record_impl!(@ variant($rclass, $rtype, data)) => data.encode_data(writer)),*
                }
            }

            fn decode_data(
                name: DomainName,
                ttl: u32,
                rclass: RecordClass,
                rtype: RecordType,
                len: u16,
                reader: &mut WireRead<'read>,
            ) -> Result<Self, WireError> {
                Ok(match (rclass, rtype) {
                    $(
                        dns_record_impl!(@ decode_pat($rclass, $rtype)) => {
                            <dns_record_impl!(@ data_struct($rclass, $rtype))>::decode_data(
                                name, ttl, rclass, rtype, len, reader,
                            )?
                            .into()
                        }
                    ),*
                })
            }

            fn decode_zone<'source>(
                name: DomainName,
                ttl: u32,
                rclass: RecordClass,
                rtype: RecordType,
                reader: &mut ZoneReader<'source>,
            ) -> Result<Self, ZoneError> {
                Ok(match (rclass, rtype) {
                    $(
                        dns_record_impl!(@ decode_pat($rclass, $rtype)) => {
                            <dns_record_impl!(@ data_struct($rclass, $rtype))>::decode_zone(
                                name, ttl, rclass, rtype, reader,
                            )?
                            .into()
                        }
                    ),*
                })
            }

            fn name(&self) -> &DomainName {
                match self {
                    $(dns_record_impl!(@ variant($rclass, $rtype, data)) => data.name()),*
                }
            }

            fn ttl(&self) -> u32 {
                match self {
                    $(dns_record_impl!(@ variant($rclass, $rtype, data)) => data.ttl()),*
                }
            }

            fn rclass(&self) -> RecordClass {
                match self {
                    $(dns_record_impl!(@ variant($rclass, $rtype, data)) => data.rclass()),*
                }
            }

            fn rtype(&self) -> RecordType {
                match self {
                    $(dns_record_impl!(@ variant($rclass, $rtype, data)) => data.rtype()),*
                }
            }

            fn additionals(&self, question: &Question) -> Vec<(Question, ResolveType)> {
                match self {
                    $(dns_record_impl!(@ variant($rclass, $rtype, data)) => data.additionals(question)),*
                }
            }
        }

        impl Display for Record {
            fn fmt(&self, f: &mut Formatter) -> fmt::Result {
                write!(f, "{}\t{}\t{}\t{}\t", self.name(), self.ttl(), self.rclass(), self.rtype())?;

                match self {
                    $(dns_record_impl!(@ variant($rclass, $rtype, data)) => Display::fmt(data, f)),*
                }
            }
        }

        $(
            impl From<dns_record_impl!(@ data_struct($rclass, $rtype))> for Record {
                fn from(data: dns_record_impl!(@ data_struct($rclass, $rtype))) -> Self {
                    dns_record_impl!(@ variant($rclass, $rtype, data))
                }
            }
        )*
    };
    (@ variant(_, _, $ident:ident)) => {
        Self::Other($ident)
    };
    (@ variant(_, $rtype:tt, $ident:ident)) => {
        paste! {
            Self::$rtype($ident)
        }
    };
    (@ variant($rclass:tt, $rtype:tt, $ident:ident)) => {
        paste! {
            Self::[<$rclass $rtype>]($ident)
        }
    };
    (@ data_struct(_, _)) => {
        OtherRecord
    };
    (@ data_struct(_, $rtype:tt)) => {
        paste! {
            [<$rtype Record>]
        }
    };
    (@ data_struct($rclass:tt, $rtype:tt)) => {
        paste! {
            [<$rclass $rtype Record>]
        }
    };
    (@ decode_pat(_, _)) => {
        (_, _)
    };
    (@ decode_pat(_, $rtype:tt)) => {
        (_, RecordType::$rtype)
    };
    (@ decode_pat($rclass:tt, $rtype:tt)) => {
        (RecordClass::$rclass, RecordType::$rtype)
    };
}

dns_record_impl! {
    (In, A),
    (Ch, A),
    (_, Ns),
    (_, Cname),
    (_, Soa),
    (_, Ptr),
    (_, Hinfo),
    (_, Mx),
    (_, Txt),
    (_, Rp),
    (In, Aaaa),
    (_, Loc),
    (_, Srv),
    (_, Opt),
    (_, _),
}
