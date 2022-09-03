use std::fmt::{self, Display, Formatter};

use crate::{
    opt::{OptCode, OptData},
    wire::{WireError, WireRead, WireWrite},
};

/// A padding option
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaddingOpt {
    bytes: Vec<u8>,
}

impl PaddingOpt {
    /// Constructs a new padding option
    pub fn new(bytes: &[u8]) -> Self {
        Self {
            bytes: bytes.to_vec(),
        }
    }

    /// The bytes used to pad the message
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl<'read> OptData<'read> for PaddingOpt {
    fn data_size(&self) -> usize {
        self.bytes.len()
    }

    fn encode_data(&self, writer: &mut WireWrite) -> Result<(), WireError> {
        writer.write(&self.bytes)?;

        Ok(())
    }

    fn decode_data(
        code: OptCode,
        len: u16,
        reader: &mut WireRead<'read>,
    ) -> Result<Self, WireError> {
        debug_assert_eq!(code, OptCode::Padding);

        let mut bytes = vec![0; len as usize];
        reader.read(&mut bytes)?;

        Ok(Self { bytes })
    }

    fn code(&self) -> OptCode {
        OptCode::Padding
    }
}

impl Display for PaddingOpt {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        for byte in &self.bytes {
            write!(f, "{:0>2x}", byte)?;
        }

        Ok(())
    }
}
