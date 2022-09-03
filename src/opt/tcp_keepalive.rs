use std::{
    fmt::{self, Display, Formatter},
    time::Duration,
};

use crate::{
    context::QueryContext,
    message::Message,
    opt::{OptCode, OptData},
    wire::{WireDecode, WireEncode, WireError, WireRead, WireWrite},
};

use super::OptHandleAction;

/// A tcp-keepalive option
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpKeepaliveOpt {
    timeout: Option<u16>,
}

impl TcpKeepaliveOpt {
    /// Constructs a new tcp-keepalive option
    pub fn new(timeout: Option<u16>) -> Self {
        Self { timeout }
    }

    /// Constructs a new tcp-keepalive option for a duration
    pub fn with_duration(timeout: Duration) -> Self {
        Self {
            timeout: Some((timeout.as_millis() / 100) as u16),
        }
    }

    /// The idle timeout for the TCP connection in units of 100 milliseconds
    pub fn timeout(&self) -> Option<u16> {
        self.timeout
    }

    /// The idle timeout for the TCP connection as a duration
    pub fn duration(&self) -> Duration {
        match self.timeout {
            Some(timeout) => Duration::from_millis(timeout as u64 * 100),
            None => Duration::ZERO,
        }
    }
}

impl<'read> OptData<'read> for TcpKeepaliveOpt {
    fn data_size(&self) -> usize {
        match self.timeout {
            Some(_) => 2,
            None => 0,
        }
    }

    fn encode_data(&self, writer: &mut WireWrite) -> Result<(), WireError> {
        if let Some(timeout) = self.timeout {
            timeout.encode(writer)?;
        }

        Ok(())
    }

    fn decode_data(
        code: OptCode,
        len: u16,
        reader: &mut WireRead<'read>,
    ) -> Result<Self, WireError> {
        debug_assert_eq!(code, OptCode::TcpKeepalive);

        if len == 0 {
            return Ok(Self { timeout: None });
        }

        if len != 2 {
            return Err(WireError::InvalidLength {
                expected: 2,
                actual: len as usize,
            });
        }

        let timeout = Some(u16::decode(reader)?);

        Ok(Self { timeout })
    }

    fn code(&self) -> OptCode {
        OptCode::TcpKeepalive
    }

    fn handle(
        &self,
        _: &Message,
        response: &mut Message,
        context: &mut QueryContext,
    ) -> OptHandleAction {
        let mut connection = context.connection.lock().unwrap();
        if self.timeout().is_some() {
            connection.keepalive = self.duration();
        }

        response.add_option(TcpKeepaliveOpt::with_duration(connection.keepalive).into());

        OptHandleAction::Nothing
    }
}

impl Display for TcpKeepaliveOpt {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self.timeout {
            Some(timeout) => write!(f, "{:.1}s", (timeout as f64) / 10.0),
            None => write!(f, "<unset>"),
        }
    }
}
