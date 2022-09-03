use std::{
    fmt::{self, Display, Formatter},
    ops::Range,
};

use enum_other::other;
use paste::paste;

use crate::{
    bitfield::{BitField, BitFieldAssign},
    opt::Opt,
    question::Question,
    record::{opt::OptRecord, Record, RecordData, RecordType},
    text::DomainName,
    wire::{WireDecode, WireEncode, WireError, WireRead, WireWrite},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketType {
    Query,
    Response,
}

impl From<bool> for PacketType {
    fn from(value: bool) -> Self {
        match value {
            false => Self::Query,
            true => Self::Response,
        }
    }
}

impl From<PacketType> for bool {
    fn from(value: PacketType) -> Self {
        match value {
            PacketType::Query => false,
            PacketType::Response => true,
        }
    }
}

#[other(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Opcode {
    Query = 0,
    IQuery = 1,
    Status = 2,
    Notify = 4,
    Update = 5,
}

impl Display for Opcode {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Opcode::Query => write!(f, "QUERY"),
            Opcode::IQuery => write!(f, "IQUERY"),
            Opcode::Status => write!(f, "STATUS"),
            Opcode::Notify => write!(f, "NOTIFY"),
            Opcode::Update => write!(f, "UPDATE"),
            Opcode::Other(code) => write!(f, "OP{}", code),
        }
    }
}

#[other(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseCode {
    NoError = 0,
    FormatError = 1,
    ServerFailure = 2,
    NonExistentDomain = 3,
    NotImplemented = 4,
    QueryRefused = 5,
    UnexpectedDomain = 6,
    UnexpectedRrSet = 7,
    NonExistentRrSet = 8,
    NotAuthorized = 9,
    NameNotInZone = 10,
    BadSignature = 16,
    BadKey = 17,
    BadTime = 18,
    BadMode = 19,
    BadName = 20,
    BadAlgorithm = 21,
    BadTruncation = 22,
    BadCookie = 23,
}

impl ResponseCode {
    pub fn is_extended(&self) -> bool {
        u16::from(*self) > 0b1111
    }

    pub fn header_bits(&self) -> u8 {
        (u16::from(*self) & 0b1111) as u8
    }

    pub fn extended_bits(&self) -> u8 {
        (u16::from(*self) >> 4) as u8
    }
}

impl Display for ResponseCode {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            ResponseCode::NoError => write!(f, "NOERROR"),
            ResponseCode::FormatError => write!(f, "FORMERR"),
            ResponseCode::ServerFailure => write!(f, "SERVFAIL"),
            ResponseCode::NonExistentDomain => write!(f, "NXDOMAIN"),
            ResponseCode::NotImplemented => write!(f, "NOTIMP"),
            ResponseCode::QueryRefused => write!(f, "REFUSED"),
            ResponseCode::UnexpectedDomain => write!(f, "YXDOMAIN"),
            ResponseCode::UnexpectedRrSet => write!(f, "YXRRSET"),
            ResponseCode::NonExistentRrSet => write!(f, "NXRRSET"),
            ResponseCode::NotAuthorized => write!(f, "NOTAUTH"),
            ResponseCode::NameNotInZone => write!(f, "NOTZONE"),
            ResponseCode::BadSignature => write!(f, "BADSIG"),
            ResponseCode::BadKey => write!(f, "BADKEY"),
            ResponseCode::BadTime => write!(f, "BADTIME"),
            ResponseCode::BadMode => write!(f, "BADMODE"),
            ResponseCode::BadName => write!(f, "BADNAME"),
            ResponseCode::BadAlgorithm => write!(f, "BADALG"),
            ResponseCode::BadTruncation => write!(f, "BADTRUNC"),
            ResponseCode::BadCookie => write!(f, "BADCOOKIE"),
            ResponseCode::Other(code) => write!(f, "{}", code),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    id: u16,
    packet_type: PacketType,
    opcode: Opcode,
    authoritative_answer: bool,
    truncated: bool,
    recursion_desired: bool,
    recursion_available: bool,
    zero: bool,
    authentic_data: bool,
    checking_disabled: bool,
    response_code: ResponseCode,
    udp_payload_size: u16,
    edns_version: Option<u8>,
    dnssec_ok: bool,
    extended_zero: u16,
    options: Vec<Opt>,
    questions: Vec<Question>,
    answers: Vec<Record>,
    authorities: Vec<Record>,
    additionals: Vec<Record>,
}

macro_rules! getter_setter_impl {
    ($field:ident, $type:ty) => {
        pub fn $field(&self) -> $type {
            self.$field
        }

        paste! {
            pub fn [<set_$field>](&mut self, $field: $type) -> &mut Self {
                self.$field = $field;
                self
            }
        }
    };
}

macro_rules! getter_adder_impl {
    ($field:ident, $item:ident, $type:ty) => {
        pub fn $field(&self) -> &[$type] {
            &self.$field
        }

        paste! {
            pub fn [<add_$item>](&mut self, $field: $type) -> &mut Self {
                self.$field.push($field);
                self
            }
        }
    };
}

impl Message {
    pub const FLAG_PACKET_TYPE: u16 = 15;
    pub const BITS_OPCODE: Range<u16> = 11..15;
    pub const FLAG_AUTHORITATIVE_ANSWER: u16 = 10;
    pub const FLAG_TRUNCATED: u16 = 9;
    pub const FLAG_RECURSION_DESIRED: u16 = 8;
    pub const FLAG_RECURSION_AVAILABLE: u16 = 7;
    pub const FLAG_ZERO: u16 = 6;
    pub const FLAG_AUTHENTIC_DATA: u16 = 5;
    pub const FLAG_CHECKING_DISABLED: u16 = 4;
    pub const BITS_RESPONSE_CODE: Range<u16> = 0..4;

    pub fn new(id: u16) -> Self {
        Self {
            id,
            packet_type: PacketType::Query,
            opcode: Opcode::Query,
            authoritative_answer: false,
            truncated: false,
            recursion_desired: false,
            recursion_available: false,
            zero: false,
            authentic_data: false,
            checking_disabled: false,
            response_code: ResponseCode::NoError,
            udp_payload_size: 512,
            edns_version: None,
            dnssec_ok: false,
            extended_zero: 0,
            options: Vec::new(),
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
        }
    }

    getter_setter_impl!(id, u16);
    getter_setter_impl!(packet_type, PacketType);
    getter_setter_impl!(opcode, Opcode);
    getter_setter_impl!(authoritative_answer, bool);
    getter_setter_impl!(truncated, bool);
    getter_setter_impl!(recursion_desired, bool);
    getter_setter_impl!(recursion_available, bool);
    getter_setter_impl!(zero, bool);
    getter_setter_impl!(response_code, ResponseCode);
    getter_setter_impl!(udp_payload_size, u16);
    getter_setter_impl!(edns_version, Option<u8>);
    getter_setter_impl!(dnssec_ok, bool);
    getter_setter_impl!(extended_zero, u16);
    getter_adder_impl!(options, option, Opt);
    getter_adder_impl!(questions, question, Question);
    getter_adder_impl!(answers, answer, Record);
    getter_adder_impl!(authorities, authority, Record);
    getter_adder_impl!(additionals, additional, Record);

    pub fn truncate_to(&mut self, size: usize) {
        let mut size = size as isize - 12;

        if self.edns_version.is_some() {
            // 11 = 1 (name) + 2 (rtype) + 2 (udp_payload_size) + 4 (flags) + 2 (rdlen)
            let edns_size = 11 + self.options.iter().map(Opt::size).sum::<usize>() as isize;

            if size - edns_size < 0 {
                self.edns_version = None;
                self.truncated = true;
            } else {
                size -= edns_size
            }
        }

        macro_rules! iter {
            ($name:ident, [$($next:ident),*]) => {
                for (index, resource) in self.$name.iter().enumerate() {
                    size -= resource.size() as isize;
                    if size < 0 {
                        self.$name.truncate(index);
                        $(self.$next.clear();)*
                        self.truncated = true;
                        return;
                    }
                }
            };
        }

        iter!(questions, [answers, authorities, additionals]);
        iter!(answers, [authorities, additionals]);
        iter!(authorities, [additionals]);
        iter!(additionals, []);
    }
}

impl WireEncode for Message {
    fn size(&self) -> usize {
        let header_and_edns_size = match self.edns_version {
            Some(_) => 23 + self.options.iter().map(WireEncode::size).sum::<usize>(),
            None => 12,
        };

        header_and_edns_size
            + self.questions.iter().map(WireEncode::size).sum::<usize>()
            + self.answers.iter().map(WireEncode::size).sum::<usize>()
            + self.authorities.iter().map(WireEncode::size).sum::<usize>()
            + self.additionals.iter().map(WireEncode::size).sum::<usize>()
    }

    fn encode(&self, writer: &mut WireWrite) -> Result<(), WireError> {
        self.id.encode(writer)?;

        let mut flags = 0u16;
        flags.set_flag(Self::FLAG_PACKET_TYPE, self.packet_type.into());
        flags.set_bits(Self::BITS_OPCODE, u8::from(self.opcode) as u16);
        flags.set_flag(Self::FLAG_AUTHORITATIVE_ANSWER, self.authoritative_answer);
        flags.set_flag(Self::FLAG_TRUNCATED, self.truncated);
        flags.set_flag(Self::FLAG_RECURSION_DESIRED, self.recursion_desired);
        flags.set_flag(Self::FLAG_RECURSION_AVAILABLE, self.recursion_available);
        flags.set_flag(Self::FLAG_ZERO, self.zero);
        flags.set_flag(Self::FLAG_AUTHENTIC_DATA, self.authentic_data);
        flags.set_flag(Self::FLAG_CHECKING_DISABLED, self.checking_disabled);
        flags.set_bits(
            Self::BITS_RESPONSE_CODE,
            self.response_code.header_bits() as u16,
        );
        flags.encode(writer)?;

        let edns_additional_space = if self.edns_version.is_some() { 1 } else { 0 };

        (self.questions.len() as u16).encode(writer)?;
        (self.answers.len() as u16).encode(writer)?;
        (self.authorities.len() as u16).encode(writer)?;
        (edns_additional_space + self.additionals.len() as u16).encode(writer)?;

        macro_rules! iter {
            ($name:ident) => {
                for resource in &self.$name {
                    resource.encode(writer)?;
                }
            };
        }

        iter!(questions);
        iter!(answers);
        iter!(authorities);

        if let Some(edns_version) = self.edns_version {
            let mut opt_flags = 0u32;

            opt_flags.set_bits(
                OptRecord::BITS_RESPONSE_CODE,
                self.response_code.extended_bits() as u32,
            );
            opt_flags.set_bits(OptRecord::BITS_VERSION, edns_version as u32);
            opt_flags.set_flag(OptRecord::FLAG_DNSSEC_OK, self.dnssec_ok);
            opt_flags.set_bits(OptRecord::BITS_ZERO, self.extended_zero as u32);

            Record::from(OptRecord::new(
                DomainName::from(Vec::new()),
                self.udp_payload_size(),
                opt_flags,
                &self.options,
            ))
            .encode(writer)?;
        }

        iter!(additionals);

        Ok(())
    }
}

impl<'read> WireDecode<'read> for Message {
    fn decode(reader: &mut WireRead<'read>) -> Result<Self, WireError> {
        let id = u16::decode(reader)?;

        let flags = u16::decode(reader)?;

        let packet_type = flags.get_flag(Self::FLAG_PACKET_TYPE).into();
        let opcode = (flags.get_bits(Self::BITS_OPCODE) as u8).into();

        let authoritative_answer = flags.get_flag(Self::FLAG_AUTHORITATIVE_ANSWER);
        let truncated = flags.get_flag(Self::FLAG_TRUNCATED);
        let recursion_desired = flags.get_flag(Self::FLAG_RECURSION_DESIRED);
        let recursion_available = flags.get_flag(Self::FLAG_RECURSION_AVAILABLE);
        let zero = flags.get_flag(Self::FLAG_ZERO);
        let authentic_data = flags.get_flag(Self::FLAG_AUTHENTIC_DATA);
        let checking_disabled = flags.get_flag(Self::FLAG_CHECKING_DISABLED);
        let mut response_code = flags.get_bits(Self::BITS_RESPONSE_CODE).into();

        let question_count = u16::decode(reader)?;
        let answer_count = u16::decode(reader)?;
        let authority_count = u16::decode(reader)?;
        let additional_count = u16::decode(reader)?;

        macro_rules! iter {
            ($name:ident, $count:ident, $type:ty) => {
                let mut $name = Vec::with_capacity($count as usize);
                for _ in 0..$count {
                    $name.push(<$type>::decode(reader)?);
                }
            };
        }

        iter!(questions, question_count, Question);
        iter!(answers, answer_count, Record);
        iter!(authorities, authority_count, Record);
        iter!(additionals, additional_count, Record);

        let mut udp_payload_size = 512;
        let mut edns_version = None;
        let mut dnssec_ok = false;
        let mut extended_zero = 0;

        let mut options = Vec::new();

        let mut additional_iter = additionals.iter();
        let opt_index = additional_iter.position(|record| record.rtype() == RecordType::Opt);
        if additional_iter.any(|record| record.rtype() == RecordType::Opt) {
            return Err(WireError::UnsupportedFormat);
        }

        if let Some(Record::Opt(edns_data)) = opt_index.map(|index| additionals.swap_remove(index))
        {
            udp_payload_size = edns_data.udp_payload_size().max(512);
            options = edns_data.options().to_vec();

            let opt_flags = edns_data.flags();
            response_code = ResponseCode::from(
                (opt_flags.get_bits(OptRecord::BITS_RESPONSE_CODE) as u16) << 4
                    | u16::from(response_code),
            );
            edns_version = Some(opt_flags.get_bits(OptRecord::BITS_VERSION) as u8);
            dnssec_ok = opt_flags.get_flag(OptRecord::FLAG_DNSSEC_OK);
            extended_zero = opt_flags.get_bits(OptRecord::BITS_ZERO) as u16;
        }

        Ok(Self {
            id,
            packet_type,
            opcode,
            authoritative_answer,
            truncated,
            recursion_desired,
            recursion_available,
            zero,
            authentic_data,
            checking_disabled,
            response_code,
            edns_version,
            udp_payload_size,
            dnssec_ok,
            extended_zero,
            options,
            questions,
            answers,
            authorities,
            additionals,
        })
    }
}

impl Display for Message {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        macro_rules! flag {
            ($cond:expr, $($repr:expr),+) => {
                if $cond {
                    write!(f, $($repr),+)?;
                }
            };
        }

        write!(
            f,
            "opcode: {}; status: {}; id: {}; flags:",
            self.opcode, self.response_code, self.id,
        )?;
        flag!(self.packet_type.into(), " qr");
        flag!(self.authoritative_answer, " aa");
        flag!(self.truncated, " tc");
        flag!(self.recursion_desired, " rd");
        flag!(self.recursion_available, " ra");
        flag!(self.authentic_data, " ad");
        flag!(self.checking_disabled, " cd");
        flag!(self.checking_disabled, " z");

        if let Some(edns_version) = self.edns_version {
            write!(f, "\nEDNS({}); flags:", edns_version)?;
            flag!(self.dnssec_ok, " do");
            flag!(self.extended_zero > 0, "; z: {:x}", self.extended_zero);
            write!(f, "; udp: {}", self.udp_payload_size)?;
            for option in &self.options {
                write!(f, "\nOPT {}", option)?;
            }
        }

        macro_rules! write_resources {
            ($($type:ident: $label:literal),+ $(,)?) => {
                $(
                    for resource in &self.$type {
                        write!(f, "\n{}: {}", $label, resource)?;
                    }
                )+
            };
        }
        write_resources!(
            questions: "QD",
            answers: "AN",
            authorities: "NS",
            additionals: "AR",
        );

        Ok(())
    }
}
