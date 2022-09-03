use std::{
    error::Error,
    fmt::{Debug, Display},
    mem,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireError {
    UnexpectedEnd { size: usize, tried: usize },
    InvalidLength { expected: usize, actual: usize },
    UnsupportedFormat,
}

impl Display for WireError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        Debug::fmt(self, f)
    }
}

impl Error for WireError {}

/// A trait that represents a value that can be encoded as binary data for the DNS protocol
pub trait WireEncode {
    /// Returns an estimated size of this value in bytes
    fn size(&self) -> usize;

    /// Encodes the value into a given writer
    fn encode(&self, writer: &mut WireWrite) -> Result<(), WireError>;
}

/// A writer for binary data
pub struct WireWrite {
    buffer: Vec<u8>,
}

impl WireWrite {
    /// Constructs a new writer
    pub fn new() -> Self {
        Self { buffer: Vec::new() }
    }

    /// Constructs a new writer with a preallocated capacity
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            buffer: Vec::with_capacity(capacity),
        }
    }

    /// Writes a slice of bytes to the end of the writer
    pub fn write(&mut self, bytes: &[u8]) -> Result<(), WireError> {
        self.buffer.extend_from_slice(bytes);
        Ok(())
    }

    /// The buffer of bytes this writer has written
    pub fn buffer(&self) -> &[u8] {
        &self.buffer
    }
}

impl Default for WireWrite {
    fn default() -> Self {
        Self::new()
    }
}

/// Encodes a value to binary data
pub fn to_wire<E>(value: &E) -> Result<Vec<u8>, WireError>
where
    E: WireEncode,
{
    let mut encoder = WireWrite::with_capacity(value.size());
    value.encode(&mut encoder)?;
    Ok(encoder.buffer)
}

/// A trait that represents a value that can be decoded from binary data for the DNS protocol
pub trait WireDecode<'read>: Sized {
    /// Decodes a value from a given writer
    fn decode(reader: &mut WireRead<'read>) -> Result<Self, WireError>;
}

/// A reader for binary data
pub struct WireRead<'read> {
    buffer: &'read [u8],
    pos: usize,
}

impl<'read> WireRead<'read> {
    /// Constructs a new reader
    pub fn new(buffer: &'read [u8]) -> Self {
        Self { buffer, pos: 0 }
    }

    /// Reads bytes into the given slice
    pub fn read(&mut self, bytes: &mut [u8]) -> Result<(), WireError> {
        self.peek(bytes)?;
        self.pos += bytes.len();

        Ok(())
    }

    /// Reads bytes into the given slice without advancing the position for the next read
    pub fn peek(&self, bytes: &mut [u8]) -> Result<(), WireError> {
        if self.pos + bytes.len() > self.buffer.len() {
            return Err(WireError::UnexpectedEnd {
                size: self.buffer.len(),
                tried: self.pos + bytes.len() - 1,
            });
        }

        bytes.copy_from_slice(&self.buffer[self.pos..self.pos + bytes.len()]);

        Ok(())
    }

    /// Moves the position of the reader to a given index
    pub fn seek_to(&mut self, index: usize) {
        self.pos = index;
    }

    /// Returns the current index of the reader
    pub fn pos(&self) -> usize {
        self.pos
    }
}

/// Decodes a value from binary data
pub fn from_wire<'read, D>(buffer: &'read [u8]) -> Result<D, WireError>
where
    D: WireDecode<'read>,
{
    let mut decoder = WireRead::new(buffer);
    D::decode(&mut decoder)
}

macro_rules! primitive_wire_impl {
    ($($primitive:ty)*) => {
        $(
            impl WireEncode for $primitive {
                fn size(&self) -> usize {
                    std::mem::size_of::<$primitive>()
                }

                fn encode(&self, writer: &mut WireWrite) -> Result<(), WireError> {
                    writer.write(&<$primitive>::to_be_bytes(*self))
                }
            }

            impl<'read> WireDecode<'read> for $primitive {
                fn decode(reader: &mut WireRead<'read>) -> Result<Self, WireError> {
                    let mut buf = [0u8; mem::size_of::<$primitive>()];
                    reader.read(&mut buf)?;
                    Ok(<$primitive>::from_be_bytes(buf))
                }
            }
        )*
    };
}

primitive_wire_impl!(u8 u16 u32 u64 u128 i8 i16 i32 i64 i128 f32 f64);
