use std::fmt::{self, Display, Formatter};

use crate::{
    context::QueryContext,
    message::Message,
    opt::{OptCode, OptData},
    wire::{WireError, WireRead, WireWrite},
};

use super::OptHandleAction;

/// A name server identifier option
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameServerIdentifierOpt {
    identity: Vec<u8>,
}

impl NameServerIdentifierOpt {
    /// Constructs a new name server identifier option
    pub fn new(identity: &[u8]) -> Self {
        Self {
            identity: identity.to_vec(),
        }
    }

    /// The identity of the name server
    pub fn identity(&self) -> &[u8] {
        &self.identity
    }
}

impl<'read> OptData<'read> for NameServerIdentifierOpt {
    fn data_size(&self) -> usize {
        self.identity.len()
    }

    fn encode_data(&self, writer: &mut WireWrite) -> Result<(), WireError> {
        writer.write(&self.identity)
    }

    fn decode_data(
        code: OptCode,
        len: u16,
        reader: &mut WireRead<'read>,
    ) -> Result<Self, WireError> {
        debug_assert_eq!(code, OptCode::NameServerIdentifier);

        let mut identity = vec![0; len as usize];
        reader.read(&mut identity)?;

        Ok(Self { identity })
    }

    fn code(&self) -> OptCode {
        OptCode::NameServerIdentifier
    }

    fn handle(
        &self,
        _: &Message,
        response: &mut Message,
        context: &mut QueryContext,
    ) -> OptHandleAction {
        if !context.config.server.identity_enabled {
            return OptHandleAction::Nothing;
        }

        response
            .add_option(NameServerIdentifierOpt::new(&context.config.server.identity_name).into());

        OptHandleAction::Nothing
    }
}

impl Display for NameServerIdentifierOpt {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        if self.identity.is_empty() {
            return write!(f, "<request>");
        }

        for byte in &self.identity {
            write!(f, "{:0>2x}", byte)?;
        }

        write!(f, " (\"")?;
        for byte in &self.identity {
            match byte {
                b' '..=b'~' => {
                    if *byte == b'\\' || *byte == b'"' {
                        write!(f, "\\")?;
                    }
                    write!(f, "{}", *byte as char)?;
                }
                _ => write!(f, "\\{:0>3}", byte)?,
            }
        }
        write!(f, "\")")?;

        Ok(())
    }
}
