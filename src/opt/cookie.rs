use std::{
    fmt::{self, Display, Formatter},
    hash::Hasher,
    net::IpAddr,
    time::SystemTime,
};

use siphasher::sip::SipHasher24;

use crate::{
    context::{CookieStrategy, QueryContext},
    message::ResponseCode,
    opt::{OptCode, OptData},
    serial::Serial,
    wire::{WireDecode, WireEncode, WireError, WireRead, WireWrite},
};

use super::OptHandleAction;

/// A cookie option
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CookieOpt {
    client: Vec<u8>,
    server: Vec<u8>,
}

impl CookieOpt {
    /// Constructs a new cookie option
    pub fn new(client: &[u8], server: &[u8]) -> Self {
        assert_eq!(client.len(), 8, "Client cookie must be 8 in length");
        assert!(
            server.is_empty() || (8..=32).contains(&server.len()),
            "Server cookie must be empty or between 8 and 32 in length",
        );

        Self {
            client: client.to_vec(),
            server: server.to_vec(),
        }
    }

    /// An 8 byte client cookie
    pub fn client(&self) -> &[u8] {
        &self.client
    }

    /// An empty or 8 to 32 byte server cookie
    pub fn server(&self) -> &[u8] {
        &self.server
    }

    /// Returns a new cookie for a given cookie option in a request
    pub fn response(&self, context: &QueryContext) -> Self {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|duration| duration.as_secs() as u32)
            .unwrap_or_else(|err| -(err.duration().as_secs() as i64) as u32);

        let mut writer = WireWrite::with_capacity(16);
        writer.write(&[1, 0, 0, 0]).unwrap();
        now.encode(&mut writer).unwrap();

        let mut hasher = SipHasher24::new_with_key(&context.config.server.cookie_secret);
        hasher.write(&self.client);
        hasher.write(&[1, 0, 0, 0]);
        hasher.write_u32(now);
        match context.connection.lock().unwrap().addr.ip() {
            IpAddr::V4(ip) => hasher.write(&ip.octets()),
            IpAddr::V6(ip) => hasher.write(&ip.octets()),
        }

        let hash = hasher.finish();
        hash.encode(&mut writer).unwrap();

        Self {
            client: self.client.clone(),
            server: writer.buffer().to_vec(),
        }
    }

    /// Validates the cookie for correctness when validation is enabled
    pub fn validate(&self, context: &QueryContext) -> bool {
        if context.config.server.cookie_strategy == CookieStrategy::Off {
            return true;
        }

        if self.server.is_empty()
            && context.config.server.cookie_strategy == CookieStrategy::Validate
        {
            return true;
        }

        if self.server.len() != 16 {
            return false;
        }

        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|duration| duration.as_secs() as u32)
            .unwrap_or_else(|err| u32::MAX - err.duration().as_secs() as u32);

        let mut reader = WireRead::new(&self.server);

        let version = u8::decode(&mut reader).unwrap();
        if version != 1 {
            return false;
        }

        let mut reserved = [0; 3];
        reader.read(&mut reserved).unwrap();

        let timestamp = Serial::from(u32::decode(&mut reader).unwrap());

        if Serial::from(now.wrapping_sub(3600)) >= timestamp
            && timestamp >= Serial::from(now.wrapping_add(300))
        {
            return false;
        }

        let mut hasher = SipHasher24::new_with_key(&context.config.server.cookie_secret);
        hasher.write(&self.client);
        hasher.write_u8(1);
        hasher.write(&reserved);
        hasher.write_u32(timestamp.into());
        match context.connection.lock().unwrap().addr.ip() {
            IpAddr::V4(ip) => hasher.write(&ip.octets()),
            IpAddr::V6(ip) => hasher.write(&ip.octets()),
        }

        let hash = hasher.finish();
        let expected_hash = u64::decode(&mut reader).unwrap();

        hash == expected_hash
    }
}

impl<'read> OptData<'read> for CookieOpt {
    fn data_size(&self) -> usize {
        self.client.len() + self.server.len()
    }

    fn encode_data(&self, writer: &mut WireWrite) -> Result<(), WireError> {
        writer.write(&self.client)?;
        writer.write(&self.server)?;

        Ok(())
    }

    fn decode_data(
        code: OptCode,
        len: u16,
        reader: &mut WireRead<'read>,
    ) -> Result<Self, WireError> {
        debug_assert_eq!(code, OptCode::Cookie);

        if !matches!(len, 8 | 16..=40) {
            return Err(WireError::InvalidLength {
                expected: 8,
                actual: len as usize,
            });
        }

        let mut client = vec![0; 8];
        reader.read(&mut client)?;

        let mut server = vec![0; len as usize - 8];
        reader.read(&mut server)?;

        Ok(Self { client, server })
    }

    fn code(&self) -> OptCode {
        OptCode::Cookie
    }

    fn handle(
        &self,
        _: &crate::message::Message,
        response: &mut crate::message::Message,
        context: &mut crate::context::QueryContext,
    ) -> OptHandleAction {
        if !context.config.server.cookie_enabled {
            return OptHandleAction::Nothing;
        }

        response.add_option(self.response(context).into());

        if !self.validate(context) {
            response.set_response_code(ResponseCode::BadCookie);
            return OptHandleAction::ReturnEarly;
        }

        OptHandleAction::Nothing
    }
}

impl Display for CookieOpt {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "C: ")?;
        for byte in &self.client {
            write!(f, "{:0>2x}", byte)?;
        }

        if !self.server.is_empty() {
            write!(f, "; S: ")?;
            for byte in &self.server {
                write!(f, "{:0>2x}", byte)?;
            }
        }

        Ok(())
    }
}
