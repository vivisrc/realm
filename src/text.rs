use std::{
    error::Error,
    fmt::{self, Debug, Display, Formatter},
    hash::{Hash, Hasher},
    iter::Map,
    slice::Iter,
    str::FromStr,
};

use crate::wire::{WireDecode, WireEncode, WireError, WireRead, WireWrite};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TextParseError {
    UnexpectedEnd,
    InvalidString,
    UnknownEscape(String),
}

impl Display for TextParseError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        Debug::fmt(&self, f)
    }
}

impl Error for TextParseError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TextParseResult {
    FoundDelimiter(usize, Vec<u8>),
    FoundWhitespace(usize, Vec<u8>),
    EndOfString(usize, Vec<u8>),
    UnknownEscape(String),
}

/// Parses text until a given delimiter, taking escape sequences into consideration.
///
/// Returns a vector of bytes, alongside the index of the last character read.
///
/// The supported escape sequences are:
/// - backslash literals (`"\\\\"` -> `"\\"`);
/// - the delimiter character given (e.g. `"\."` -> `"."`);
/// - a sequence of 3 digits to be interpreted as a byte (e.g. `"\104"` -> `"h"`);
///
/// # Examples
///
/// ```
/// assert_eq!(parse_text("example text.", '.', true), FoundDelimiter(12, b"example text".to_vec()));
/// assert_eq!(parse_text("lorem ipsum.", '.', false), FoundWhitespace(5, b"lorem".to_vec()));
/// assert_eq!(parse_text("foobar", '.', false), EndOfString(6, b"foobar".to_vec()));
/// ```
pub fn parse_text(text: &str, delimiter: char, allow_whitespace: bool) -> TextParseResult {
    let mut bytes = Vec::new();
    let mut chars = text.char_indices();
    let mut index = 0;

    macro_rules! next {
        () => {
            match chars.next() {
                Some((i, char)) => {
                    index = i;
                    char
                }
                None => {
                    return TextParseResult::EndOfString(index + 1, bytes);
                }
            }
        };
    }

    loop {
        let char = next!();

        if char == delimiter {
            return TextParseResult::FoundDelimiter(index, bytes);
        }

        if !allow_whitespace && char.is_whitespace() {
            return TextParseResult::FoundWhitespace(index, bytes);
        }

        if char != '\\' {
            bytes.extend_from_slice(char.to_string().as_bytes());
            continue;
        }

        let escaped_char = next!();

        match escaped_char {
            '\\' => bytes.push(b'\\'),
            '0'..='9' => {
                let chars = [escaped_char, next!(), next!()];

                let mut num = 0;
                for (digit, char) in [2, 1, 0].into_iter().zip(chars) {
                    num += 10u32.pow(digit)
                        * match char.to_digit(10) {
                            Some(n) => n,
                            None => {
                                return TextParseResult::UnknownEscape(chars.into_iter().collect());
                            }
                        };
                }

                if num > u8::MAX as u32 {
                    return TextParseResult::UnknownEscape(chars.into_iter().collect());
                }

                bytes.push(num as u8);
            }
            _ => {
                if escaped_char != delimiter {
                    return TextParseResult::UnknownEscape(escaped_char.to_string());
                }

                bytes.extend_from_slice(escaped_char.to_string().as_bytes());
            }
        }
    }
}

/// Represents a single label for a node
#[derive(Clone, Eq)]
pub struct Label(Vec<u8>);

impl Label {
    /// An iterator of normalized bytes for comparisons between two labels
    fn normalized_bytes(&self) -> Map<Iter<u8>, fn(&u8) -> u8> {
        self.0.iter().map(u8::to_ascii_uppercase)
    }
}

impl WireEncode for Label {
    fn size(&self) -> usize {
        self.0.len() + 1
    }

    fn encode(&self, writer: &mut WireWrite) -> Result<(), WireError> {
        (self.0.len() as u8).encode(writer)?;
        writer.write(&self.0)?;

        Ok(())
    }
}

impl<'read> WireDecode<'read> for Label {
    fn decode(reader: &mut WireRead<'read>) -> Result<Self, WireError> {
        let len = u8::decode(reader)?;
        let mut buf = vec![0; len as usize];
        reader.read(&mut buf)?;

        Ok(Self(buf))
    }
}

impl Debug for Label {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "DnsLabel({})", self)
    }
}

impl Display for Label {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        for byte in &self.0 {
            match byte {
                b'!'..=b'~' => {
                    if *byte == b'\\' || *byte == b'.' {
                        write!(f, "\\")?;
                    }
                    write!(f, "{}", *byte as char)?;
                }
                _ => write!(f, "\\{:0>3}", byte)?,
            }
        }
        write!(f, ".")?;

        Ok(())
    }
}

impl FromStr for Label {
    type Err = TextParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match parse_text(s, '.', false) {
            TextParseResult::FoundDelimiter(index, text) if index + 1 == s.len() => Ok(Self(text)),
            TextParseResult::EndOfString(_, _) => Err(TextParseError::UnexpectedEnd),
            TextParseResult::UnknownEscape(sequence) => {
                Err(TextParseError::UnknownEscape(sequence))
            }
            _ => Err(TextParseError::InvalidString),
        }
    }
}

impl PartialEq for Label {
    fn eq(&self, other: &Self) -> bool {
        if self.0.len() != other.0.len() {
            return false;
        }

        self.normalized_bytes().eq(other.normalized_bytes())
    }
}

impl Hash for Label {
    fn hash<H>(&self, state: &mut H)
    where
        H: Hasher,
    {
        state.write_usize(self.0.len());
        for byte in self.normalized_bytes() {
            state.write_u8(byte)
        }
    }
}

impl From<Vec<u8>> for Label {
    fn from(bytes: Vec<u8>) -> Self {
        assert!(!bytes.is_empty(), "DNS label cannot be empty");
        assert!(bytes.len() < 64, "DNS label cannot be 64 bytes or longer");
        Self(bytes)
    }
}

impl From<Label> for Vec<u8> {
    fn from(label: Label) -> Self {
        label.0
    }
}

/// A name in the domain name system
pub trait Name: Sized + From<Vec<Label>> {
    /// If this name supports compression
    const COMPRESS: bool;

    /// The labels part of this name
    fn labels(&self) -> &[Label];
}

/// A compressible name in the domain name system
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct DomainName(Vec<Label>);

impl Name for DomainName {
    const COMPRESS: bool = true;

    fn labels(&self) -> &[Label] {
        &self.0
    }
}

/// An incompressible name in the domain name system
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct HostName(Vec<Label>);

impl Name for HostName {
    const COMPRESS: bool = false;

    fn labels(&self) -> &[Label] {
        &self.0
    }
}

impl<T> WireEncode for T
where
    T: Name,
{
    fn size(&self) -> usize {
        self.labels().iter().map(Label::size).sum::<usize>() + 1
    }

    fn encode(&self, writer: &mut WireWrite) -> Result<(), WireError> {
        for part in self.labels() {
            part.encode(writer)?;
        }
        0u8.encode(writer)?;

        Ok(())
    }
}

impl<'read, T> WireDecode<'read> for T
where
    T: Name,
{
    fn decode(reader: &mut WireRead<'read>) -> Result<Self, WireError> {
        let mut seek_to_before_return = None;
        let mut visited_positions = Vec::with_capacity(1);

        let mut labels = Vec::new();
        loop {
            visited_positions.push(reader.pos());

            let mut label_type = [0u8];
            reader.peek(&mut label_type)?;

            match label_type[0] >> 6 {
                0b00 => {
                    let len = u8::decode(reader)?;
                    if len == 0 {
                        break;
                    }

                    let mut buf = vec![0; len as usize];
                    reader.read(&mut buf)?;
                    labels.push(Label(buf))
                }
                0b11 if Self::COMPRESS => {
                    let pointer = (u16::decode(reader)? ^ (0b11 << 14)) as usize;
                    if visited_positions.contains(&pointer) {
                        if let Some(pos) = seek_to_before_return {
                            reader.seek_to(pos)
                        }
                        return Err(WireError::UnsupportedFormat);
                    }

                    if seek_to_before_return.is_none() {
                        seek_to_before_return = Some(reader.pos())
                    }

                    reader.seek_to(pointer);
                }
                _ => {
                    if let Some(pos) = seek_to_before_return {
                        reader.seek_to(pos)
                    }
                    return Err(WireError::UnsupportedFormat);
                }
            }
        }

        if let Some(pos) = seek_to_before_return {
            reader.seek_to(pos)
        }

        Ok(Self::from(labels))
    }
}

macro_rules! name_impl {
    ($type:ty) => {
        impl Debug for $type {
            fn fmt(&self, f: &mut Formatter) -> fmt::Result {
                write!(f, "{}({})", stringify!($type), self)
            }
        }

        impl Display for $type {
            fn fmt(&self, f: &mut Formatter) -> fmt::Result {
                for label in &self.0 {
                    Display::fmt(&label, f)?;
                }
                if self.0.is_empty() {
                    write!(f, ".")?;
                }

                Ok(())
            }
        }

        impl FromStr for $type {
            type Err = TextParseError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                let mut pos = 0;
                let mut labels = Vec::new();

                while pos != s.len() {
                    match parse_text(s.get(pos..).unwrap(), '.', false) {
                        TextParseResult::FoundDelimiter(index, label) => {
                            pos += index + 1;

                            if label.is_empty() {
                                if labels.is_empty() {
                                    return Ok(Self(labels));
                                } else {
                                    return Err(TextParseError::InvalidString);
                                }
                            }

                            labels.push(Label(label));
                        }
                        TextParseResult::EndOfString(_, _) => {
                            return Err(TextParseError::UnexpectedEnd)
                        }
                        TextParseResult::UnknownEscape(sequence) => {
                            return Err(TextParseError::UnknownEscape(sequence));
                        }
                        _ => return Err(TextParseError::InvalidString),
                    };
                }

                Ok(Self(labels))
            }
        }

        impl From<Vec<Label>> for $type {
            fn from(bytes: Vec<Label>) -> Self {
                let mut parts = Vec::with_capacity(bytes.len());
                for part in bytes {
                    parts.push(part)
                }
                Self(parts)
            }
        }

        impl From<$type> for Vec<Label> {
            fn from(name: $type) -> Self {
                let mut parts = Vec::with_capacity(name.0.len());
                for part in name.0 {
                    parts.push(part)
                }
                parts
            }
        }
    };
}

name_impl!(DomainName);
name_impl!(HostName);

impl From<HostName> for DomainName {
    fn from(name: HostName) -> Self {
        Self(name.0)
    }
}

impl From<DomainName> for HostName {
    fn from(name: DomainName) -> Self {
        Self(name.0)
    }
}

/// A text string in the DNS system, most often UTF-8 but should be treated as binary data
#[derive(Clone, PartialEq, Eq)]
pub struct Text(Vec<u8>);

impl WireEncode for Text {
    fn size(&self) -> usize {
        self.0.len() + 1
    }

    fn encode(&self, writer: &mut WireWrite) -> Result<(), WireError> {
        (self.0.len() as u8).encode(writer)?;
        writer.write(&self.0)?;

        Ok(())
    }
}

impl<'read> WireDecode<'read> for Text {
    fn decode(reader: &mut WireRead<'read>) -> Result<Self, WireError> {
        let len = u8::decode(reader)?;
        let mut buf = vec![0; len as usize];
        reader.read(&mut buf)?;

        Ok(Self(buf))
    }
}

impl Debug for Text {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "DnsString({})", self)
    }
}

impl Display for Text {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "\"")?;
        for byte in &self.0 {
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
        write!(f, "\"")?;

        Ok(())
    }
}

impl FromStr for Text {
    type Err = TextParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.chars().next() {
            Some('"') => (),
            _ => return Err(TextParseError::InvalidString),
        }

        match parse_text(s.get(1..).unwrap(), '"', true) {
            TextParseResult::FoundDelimiter(index, text) => {
                if index + 2 != s.len() {
                    return Err(TextParseError::InvalidString);
                }
                Ok(Self(text))
            }
            TextParseResult::EndOfString(_, _) => Err(TextParseError::UnexpectedEnd),
            TextParseResult::UnknownEscape(sequence) => {
                Err(TextParseError::UnknownEscape(sequence))
            }
            _ => Err(TextParseError::InvalidString),
        }
    }
}

impl From<Vec<u8>> for Text {
    fn from(bytes: Vec<u8>) -> Self {
        assert!(
            bytes.len() < 256,
            "DNS string cannot be 256 bytes or longer",
        );
        Self(bytes)
    }
}

impl From<Text> for Vec<u8> {
    fn from(string: Text) -> Self {
        string.0
    }
}

#[cfg(test)]
mod tests {
    use test_case::test_case;

    use super::*;
    use crate::wire::{from_wire, to_wire};

    #[test_case("example text.", '.', true => TextParseResult::FoundDelimiter(12, b"example text".to_vec()); "delimiter")]
    #[test_case("lorem ipsum.", '.', false => TextParseResult::FoundWhitespace(5, b"lorem".to_vec()); "whitespace")]
    #[test_case("foobar", '.', false => TextParseResult::EndOfString(6, b"foobar".to_vec()); "end")]
    fn parse(text: &str, delimiter: char, allow_whitespace: bool) -> TextParseResult {
        parse_text(text, delimiter, allow_whitespace)
    }

    #[test_case("example-label".as_bytes(), "example-label."; "basic")]
    #[test_case("escaped.dot".as_bytes(), "escaped\\.dot."; "escaped dot")]
    #[test_case(&[0, 1, 255], "\\000\\001\\255."; "escaped bytes")]
    #[test_case(&[], "."; "empty")]
    fn label_fmt(label: &[u8], formatted: &str) {
        assert_eq!(Label::from_str(formatted), Ok(Label(label.to_vec())));
        assert_eq!(Label(label.to_vec()).to_string(), formatted);
    }

    #[test_case("example-label" => TextParseError::UnexpectedEnd; "missing dot")]
    #[test_case("example-label.." => TextParseError::InvalidString; "trailing dot")]
    #[test_case("\\n." => TextParseError::UnknownEscape("n".to_string()); "bad escape")]
    #[test_case("\\0." => TextParseError::UnexpectedEnd; "unfinished escape")]
    fn label_parse_err(parse: &str) -> TextParseError {
        Label::from_str(parse).unwrap_err()
    }

    #[test_case("\x05hello".as_bytes(), Label("hello".as_bytes().to_vec()); "basic")]
    #[test_case("\x06test.\0".as_bytes(), Label("test.\0".as_bytes().to_vec()); "escapes")]
    #[test_case(&[0], Label(vec![]); "empty")]
    fn label_wire(wire: &[u8], label: Label) {
        assert_eq!(to_wire(&label).unwrap(), wire);
        assert_eq!(from_wire::<Label>(wire).unwrap(), label);
    }

    #[test_case(Label("hello".as_bytes().to_vec()), Label("hello".as_bytes().to_vec()), true; "basic")]
    #[test_case(Label("test".as_bytes().to_vec()), Label("TEST".as_bytes().to_vec()), true; "case insensitive")]
    #[test_case(Label("hotdog".as_bytes().to_vec()), Label("sandwich".as_bytes().to_vec()), false; "inequality")]
    fn label_eq(left: Label, right: Label, eq: bool) {
        if eq {
            assert_eq!(left, right);
        } else {
            assert_ne!(left, right);
        }
    }

    #[test_case(&["example".as_bytes(), "name".as_bytes()], "example.name."; "basic")]
    #[test_case(&["escaped.dot".as_bytes()], "escaped\\.dot."; "escaped dot")]
    #[test_case(&[&[0, 1, 255]], "\\000\\001\\255."; "escaped bytes")]
    #[test_case(&[], "."; "empty")]
    fn name_fmt(name: &[&[u8]], formatted: &str) {
        assert_eq!(
            DomainName::from_str(formatted),
            Ok(DomainName::from(
                name.iter()
                    .map(|x| Label::from(x.to_vec()))
                    .collect::<Vec<_>>(),
            )),
        );
        assert_eq!(
            DomainName::from(
                name.iter()
                    .map(|x| Label::from(x.to_vec()))
                    .collect::<Vec<_>>(),
            )
            .to_string(),
            formatted,
        );
    }

    #[test_case("example-label" => TextParseError::UnexpectedEnd; "missing dot")]
    #[test_case("example-label.." => TextParseError::InvalidString; "trailing dot")]
    #[test_case("example..com" => TextParseError::InvalidString; "double dot")]
    #[test_case("\\n." => TextParseError::UnknownEscape("n".to_string()); "bad escape")]
    #[test_case("\\0." => TextParseError::UnexpectedEnd; "unfinished escape")]
    fn name_parse_err(parse: &str) -> TextParseError {
        DomainName::from_str(parse).unwrap_err()
    }

    #[test_case("\x05hello\x05world\0".as_bytes(), &[Label("hello".as_bytes().to_vec()), Label("world".as_bytes().to_vec())]; "basic")]
    #[test_case("\x06test.\0\0".as_bytes(), &[Label("test.\0".as_bytes().to_vec())]; "escapes")]
    #[test_case(&[0], &[]; "empty")]
    fn name_wire(wire: &[u8], name: &[Label]) {
        assert_eq!(to_wire(&DomainName::from(name.to_vec())).unwrap(), wire);
        assert_eq!(
            from_wire::<DomainName>(wire).unwrap(),
            DomainName::from(name.to_vec()),
        );

        assert_eq!(to_wire(&HostName::from(name.to_vec())).unwrap(), wire);
        assert_eq!(
            from_wire::<HostName>(wire).unwrap(),
            HostName::from(name.to_vec()),
        );
    }

    #[test_case(&[3, b'c', b'o', b'm', 0, 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0b11000000, 0], 5, Ok(DomainName(vec![Label("example".as_bytes().to_vec()), Label("com".as_bytes().to_vec())])); "basic")]
    #[test_case(&[0b11000000, 0], 0, Err(WireError::UnsupportedFormat); "deny recursion")]
    #[test_case(&[0b11000000, 2], 0, Err(WireError::UnexpectedEnd { size: 2, tried: 2 }); "out of bounds")]
    fn name_wire_pointer(wire: &[u8], start_at: usize, expect: Result<DomainName, WireError>) {
        let mut reader = WireRead::new(wire);
        reader.seek_to(start_at);
        assert_eq!(DomainName::decode(&mut reader), expect);

        let mut reader = WireRead::new(wire);
        reader.seek_to(start_at);
        assert_eq!(
            HostName::decode(&mut reader),
            Err(WireError::UnsupportedFormat),
        );
    }

    #[test_case("text".as_bytes(), r#""text""#; "basic")]
    #[test_case("escaped\"quote".as_bytes(), r#""escaped\"quote""#; "escaped quote")]
    #[test_case(&[0, 1, 255], r#""\000\001\255""#; "escaped bytes")]
    #[test_case(&[], r#""""#; "empty")]
    fn text_fmt(text: &[u8], formatted: &str) {
        assert_eq!(Text::from_str(formatted), Ok(Text(text.to_vec())),);
        assert_eq!(Text(text.to_vec()).to_string(), formatted);
    }

    #[test_case(r#"example string"# => TextParseError::InvalidString; "missing quotes")]
    #[test_case(r#"example string""# => TextParseError::InvalidString; "missing start quote")]
    #[test_case(r#""example string"# => TextParseError::UnexpectedEnd; "missing end quote")]
    #[test_case(r#""test""s""# => TextParseError::InvalidString; "trailing characters")]
    #[test_case(r#""\n""# => TextParseError::UnknownEscape("n".to_string()); "bad escape")]
    #[test_case(r#""\0""# => TextParseError::UnexpectedEnd; "unfinished escape")]
    fn text_parse_err(parse: &str) -> TextParseError {
        Text::from_str(parse).unwrap_err()
    }

    #[test_case("\x05hello".as_bytes(), Text("hello".as_bytes().to_vec()); "basic")]
    #[test_case("\x06test.\0".as_bytes(), Text("test.\0".as_bytes().to_vec()); "escapes")]
    #[test_case(&[0], Text(vec![]); "empty")]
    fn text_wire(wire: &[u8], text: Text) {
        assert_eq!(to_wire(&text).unwrap(), wire);
        assert_eq!(from_wire::<Text>(wire).unwrap(), text);
    }
}
