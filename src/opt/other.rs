use std::fmt::{self, Display, Formatter};

use crate::{
    opt::{OptCode, OptData},
    wire::{WireError, WireRead, WireWrite},
};

/// Represents an arbitrary EDNS option
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OtherOpt {
    code: OptCode,
    data: Vec<u8>,
}

impl OtherOpt {
    /// Constructs a new arbitrary EDNS option
    pub fn new(code: OptCode, data: Vec<u8>) -> Self {
        Self { code, data }
    }

    /// The binary data of the option
    pub fn data(&self) -> &[u8] {
        &self.data
    }
}

impl<'read> OptData<'read> for OtherOpt {
    fn data_size(&self) -> usize {
        self.data.len()
    }

    fn encode_data(&self, writer: &mut WireWrite) -> Result<(), WireError> {
        writer.write(&self.data)
    }

    fn decode_data(
        code: OptCode,
        len: u16,
        reader: &mut WireRead<'read>,
    ) -> Result<Self, WireError> {
        let mut data = vec![0; len as usize];
        reader.read(&mut data)?;

        Ok(Self { code, data })
    }

    fn code(&self) -> OptCode {
        self.code
    }
}

impl Display for OtherOpt {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        for byte in &self.data {
            write!(f, "{:0>2x}", byte)?;
        }
        Ok(())
    }
}
