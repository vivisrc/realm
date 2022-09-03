use std::fmt::{self, Display, Formatter};

use enum_other::other;
use paste::paste;

use crate::{
    context::QueryContext,
    message::Message,
    opt::{
        cookie::CookieOpt, name_server_identifier::NameServerIdentifierOpt, other::OtherOpt,
        padding::PaddingOpt, tcp_keepalive::TcpKeepaliveOpt,
    },
    wire::{WireDecode, WireEncode, WireError, WireRead, WireWrite},
};

pub mod cookie;
pub mod name_server_identifier;
pub mod other;
pub mod padding;
pub mod tcp_keepalive;

#[other(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OptCode {
    NameServerIdentifier = 3,
    Cookie = 10,
    TcpKeepalive = 11,
    Padding = 12,
}

impl Display for OptCode {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Self::NameServerIdentifier => write!(f, "NSID"),
            Self::Cookie => write!(f, "COOKIE"),
            Self::TcpKeepalive => write!(f, "tcp-keepalive"),
            Self::Padding => write!(f, "Padding"),
            Self::Other(code) => write!(f, "OPT{}", code),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Opt {
    NameServerIdentifier(NameServerIdentifierOpt),
    Cookie(CookieOpt),
    TcpKeepalive(TcpKeepaliveOpt),
    Padding(PaddingOpt),
    Other(OtherOpt),
}

impl WireEncode for Opt {
    fn size(&self) -> usize {
        4 + self.data_size()
    }

    fn encode(&self, writer: &mut WireWrite) -> Result<(), WireError> {
        u16::from(self.code()).encode(writer)?;
        (self.data_size() as u16).encode(writer)?;

        self.encode_data(writer)?;

        Ok(())
    }
}

impl<'read> WireDecode<'read> for Opt {
    fn decode(reader: &mut WireRead<'read>) -> Result<Self, WireError> {
        let code = OptCode::from(u16::decode(reader)?);
        let len = u16::decode(reader)?;

        let data = Self::decode_data(code, len, reader)?;

        Ok(data)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OptHandleAction {
    Nothing,
    ReturnEarly,
}

pub trait OptData<'read>: Sized {
    /// The size of this option's data
    fn data_size(&self) -> usize;

    /// Encodes this option's data into the given writer
    fn encode_data(&self, writer: &mut WireWrite) -> Result<(), WireError>;

    /// Decodes a option's data from a given writer
    fn decode_data(
        code: OptCode,
        len: u16,
        reader: &mut WireRead<'read>,
    ) -> Result<Self, WireError>;

    /// The option code of this option
    fn code(&self) -> OptCode;

    fn handle(&self, _: &Message, _: &mut Message, _: &mut QueryContext) -> OptHandleAction {
        OptHandleAction::Nothing
    }
}

macro_rules! dns_opt_impl {
    ($($code:tt,)*) => {
        impl<'read> OptData<'read> for Opt {
            fn data_size(&self) -> usize {
                match self {
                    $(dns_opt_impl!(@ variant($code, data)) => data.data_size()),*
                }
            }

            fn encode_data(&self, writer: &mut WireWrite) -> Result<(), WireError> {
                match self {
                    $(dns_opt_impl!(@ variant($code, data)) => data.encode_data(writer)),*
                }
            }

            fn decode_data(
                code: OptCode,
                len: u16,
                reader: &mut WireRead<'read>,
            ) -> Result<Self, WireError> {
                Ok(match code {
                    $(
                        dns_opt_impl!(@ decode_pat($code)) => {
                            <dns_opt_impl!(@ data_struct($code))>::decode_data(
                                code, len, reader,
                            )?
                            .into()
                        }
                    ),*
                })
            }

            fn code(&self) -> OptCode {
                match self {
                    $(dns_opt_impl!(@ variant($code, data)) => data.code()),*
                }
            }

            fn handle(
                &self,
                query: &Message,
                response: &mut Message,
                context: &mut QueryContext
            ) -> OptHandleAction {
                match self {
                    $(dns_opt_impl!(@ variant($code, data)) => data.handle(query, response, context)),*
                }
            }
        }

        impl Display for Opt {
            fn fmt(&self, f: &mut Formatter) -> fmt::Result {
                write!(f, "{}: ", self.code())?;

                match self {
                    $(dns_opt_impl!(@ variant($code, data)) => Display::fmt(data, f)),*
                }
            }
        }

        $(
            impl From<dns_opt_impl!(@ data_struct($code))> for Opt {
                fn from(data: dns_opt_impl!(@ data_struct($code))) -> Self {
                    dns_opt_impl!(@ variant($code, data))
                }
            }
        )*
    };
    (@ variant(_, $ident:ident)) => {
        Self::Other($ident)
    };
    (@ variant($code:tt, $ident:ident)) => {
        paste! {
            Self::$code($ident)
        }
    };
    (@ data_struct(_)) => {
        OtherOpt
    };
    (@ data_struct($code:tt)) => {
        paste! {
            [<$code Opt>]
        }
    };
    (@ decode_pat(_)) => {
        _
    };
    (@ decode_pat($code:tt)) => {
        OptCode::$code
    };
}

dns_opt_impl! {
    NameServerIdentifier,
    Cookie,
    TcpKeepalive,
    Padding,
    _,
}
