use std::{
    error::Error,
    fmt::{self, Display, Formatter},
    str::FromStr,
};

use logos::{Lexer, Logos, Span};

use crate::{
    node::Node,
    record::{Record, RecordClass, RecordData, RecordType},
    text::{parse_text, DomainName, Name, Text, TextParseResult},
    wire::WireRead,
};

fn lex_string(lexer: &mut Lexer<ZoneToken>) -> String {
    lexer.slice().to_string()
}

fn lex_text(lex: &mut Lexer<ZoneToken>) -> Option<Text> {
    match parse_text(lex.remainder(), '"', true) {
        TextParseResult::FoundDelimiter(bytes_read, label) => {
            lex.bump(bytes_read + 1);
            Some(label.into())
        }
        _ => None,
    }
}

#[derive(Logos, Debug, PartialEq, Eq)]
pub enum ZoneToken {
    #[regex(r";[^\r\n]*", logos::skip, priority = 0)]
    #[error]
    Error,
    #[regex(r"[ \t]+")]
    Whitespace,
    #[regex(r"[\r\n]+")]
    NewLine,
    #[token("(")]
    OpenParen,
    #[token(")")]
    CloseParen,
    #[token("\"", lex_text)]
    Text(Text),
    #[regex(r#"[^; \t\r\n"()]+"#, lex_string)]
    String(String),
}

#[derive(Debug, PartialEq, Eq)]
pub enum ZoneErrorKind {
    LexerError(String),
    UnknownEscape(String),
    MissingOpeningParentheses,
    MissingClosingParentheses,
    IncompleteEntry,
    BadEntry,
    InvalidName,
    UnknownControl(String),
}

impl Display for ZoneErrorKind {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Self::LexerError(string) => write!(f, "unable to lex {:?}", string),
            Self::UnknownEscape(sequence) => {
                write!(f, "unknown escape sequence {:?}", sequence)
            }
            Self::MissingOpeningParentheses => write!(f, "missing opening parentheses"),
            Self::MissingClosingParentheses => write!(f, "missing closing parentheses"),
            Self::IncompleteEntry => write!(f, "incomplete zone entry"),
            Self::BadEntry => write!(f, "bad zone entry"),
            Self::InvalidName => write!(f, "domain name is invalid"),
            Self::UnknownControl(control) => {
                write!(f, "unknown control entry {}", control)
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct ZoneError {
    kind: ZoneErrorKind,
    span: Span,
}

impl ZoneError {
    pub fn new(kind: ZoneErrorKind, span: Span) -> Self {
        Self { kind, span }
    }

    pub fn kind(&self) -> &ZoneErrorKind {
        &self.kind
    }

    pub fn span(&self) -> &Span {
        &self.span
    }
}

impl Display for ZoneError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{} at {}..{}", self.kind, self.span.start, self.span.end)
    }
}

impl Error for ZoneError {}

#[derive(Debug)]
pub struct ZoneReader<'source> {
    lexer: Lexer<'source, ZoneToken>,
    peeked: Option<Option<ZoneToken>>,
    parentheses: usize,
    root: Node,
    origin: DomainName,
    name: Option<DomainName>,
    ttl: Option<u32>,
    rclass: Option<RecordClass>,
}

impl<'source> ZoneReader<'source> {
    /// Reads the next token, returns an error of kind [`ZoneErrorKind::IncompleteEntry`]
    /// when there are no tokens left in the current entry.
    pub fn read(&mut self) -> Result<ZoneToken, ZoneError> {
        let token = self.peeked.take().unwrap_or_else(|| self.lexer.next());

        match token {
            Some(ZoneToken::Error) => {
                return self.error(ZoneErrorKind::LexerError(self.lexer.slice().to_string()))
            }
            Some(ZoneToken::OpenParen) => self.parentheses += 1,
            Some(ZoneToken::CloseParen) => {
                if self.parentheses == 0 {
                    return self.error(ZoneErrorKind::MissingOpeningParentheses);
                }
                self.parentheses -= 1;
            }
            Some(ZoneToken::NewLine) | None => {
                // If it's zero, the end of the entry has been reached.
                if self.parentheses == 0 {
                    return self.error(ZoneErrorKind::IncompleteEntry);
                }
            }
            _ => (),
        }

        match token {
            Some(token) => Ok(token),
            // A check for zero values of parenthesis is in the match statement above.
            // If it's non-zero, we have a parenthesis that hasn't been closed.
            None => self.error(ZoneErrorKind::MissingClosingParentheses),
        }
    }

    /// Peeks the next token of the entry.
    pub fn peek(&mut self) -> Option<&ZoneToken> {
        match self
            .peeked
            .get_or_insert_with(|| self.lexer.next())
            .as_ref()
        {
            Some(ZoneToken::NewLine) => {
                // If it's zero, the end of the entry has been reached.
                if self.parentheses == 0 {
                    None
                } else {
                    Some(&ZoneToken::NewLine)
                }
            }
            token => token,
        }
    }

    /// Returns the span of the last seen (including peeked) token.
    pub fn span(&self) -> Span {
        self.lexer.span()
    }

    /// Returns an Err([`ZoneError`]) with the current span given an [`ZoneErrorKind`]
    /// for convenience.
    pub fn error<T>(&self, kind: ZoneErrorKind) -> Result<T, ZoneError> {
        Err(ZoneError::new(kind, self.span()))
    }

    /// Similar to `ZoneReader::read`, but only takes [`ZoneToken::String`] tokens and returns
    /// its value. Other tokens return an error of kind [`ZoneErrorKind::BadEntry`].
    pub fn read_string(&mut self) -> Result<String, ZoneError> {
        match self.read()? {
            ZoneToken::String(string) => Ok(string),
            _ => self.error(ZoneErrorKind::BadEntry),
        }
    }

    /// Read one or more "blank" tokens. Returning the amount of blank tokens read.
    /// If there were no tokens read, returns an error of kind [`ZoneErrorKind::BadEntry`] or
    /// [`ZoneErrorKind::IncompleteEntry`] if there are no tokens left in the entry.
    pub fn read_blank(&mut self) -> Result<usize, ZoneError> {
        let mut read = 0usize;

        loop {
            let is_blank = matches!(
                self.peek(),
                Some(
                    ZoneToken::Whitespace
                        | ZoneToken::NewLine
                        | ZoneToken::OpenParen
                        | ZoneToken::CloseParen
                )
            );

            if is_blank {
                self.read()?;
                read += 1;
                continue;
            }

            if read != 0 {
                break;
            }

            return match self.peek() {
                Some(_) => self.error(ZoneErrorKind::BadEntry),
                None => self.error(ZoneErrorKind::IncompleteEntry),
            };
        }

        Ok(read)
    }

    /// Similar to `ZoneReader::read`, but only takes [`ZoneToken::Whitespace`] tokens. Other
    /// tokens return an error of kind [`ZoneErrorKind::BadEntry`].
    pub fn read_whitespace(&mut self) -> Result<(), ZoneError> {
        match self.read()? {
            ZoneToken::Whitespace => Ok(()),
            _ => self.error(ZoneErrorKind::BadEntry),
        }
    }

    /// Similar to `ZoneReader::read_string`, but parses the value as `T`. If a parsing error
    /// occurs, an error of kind [`ZoneErrorKind::BadEntry`] is returned.
    pub fn read_parsable<T>(&mut self) -> Result<T, ZoneError>
    where
        T: FromStr,
    {
        match self.read_string()?.parse() {
            Ok(parsed) => Ok(parsed),
            Err(_) => self.error(ZoneErrorKind::BadEntry),
        }
    }

    /// Similar to `ZoneReader::read_parsable`, but splits at the first non-digit character.
    /// The remaining half of the string is returned in the second half of the tuple.
    /// Empty units may be returned and should be handled by the caller.
    pub fn read_measure<T>(&mut self) -> Result<(T, String), ZoneError>
    where
        T: FromStr,
    {
        let s = self.read_string()?;

        let index = s
            .find(|char| !matches!(char, '0'..='9' | '-' | '.'))
            .unwrap_or(s.len());

        let (value, unit) = s.split_at(index);

        match value.parse() {
            Ok(value) => Ok((value, unit.to_string())),
            Err(_) => self.error(ZoneErrorKind::BadEntry),
        }
    }

    /// Similar to `ZoneReader::read_parsable`, but is specialised to reading DNS names. Supports
    /// names both relative to the origin, and fully qualified names. If the name is `"@"`, the
    /// current origin is returned.
    pub fn read_name(&mut self) -> Result<DomainName, ZoneError> {
        let name = self.read_string()?;

        if name == "@" {
            return Ok(self.origin.clone());
        }

        let mut pos = 0;
        let mut labels = Vec::new();

        while pos != name.len() {
            match parse_text(name.get(pos..).unwrap(), '.', false) {
                TextParseResult::FoundDelimiter(index, label) => {
                    pos += index + 1;

                    if label.is_empty() {
                        if labels.is_empty() {
                            return Ok(labels.into());
                        } else {
                            return self.error(ZoneErrorKind::InvalidName);
                        }
                    }

                    labels.push(label.into());
                }
                TextParseResult::EndOfString(_, label) => {
                    labels.push(label.into());
                    labels.extend_from_slice(self.origin.labels());

                    return Ok(labels.into());
                }
                TextParseResult::UnknownEscape(sequence) => {
                    return self.error(ZoneErrorKind::UnknownEscape(sequence));
                }
                _ => return self.error(ZoneErrorKind::InvalidName),
            };
        }

        Ok(labels.into())
    }

    /// Similar to `ZoneReader::read`, but only takes [`ZoneToken::Text`] tokens and returns
    /// its value. Other tokens return an error of kind [`ZoneErrorKind::BadEntry`].
    pub fn read_text(&mut self) -> Result<Text, ZoneError> {
        match self.read()? {
            ZoneToken::Text(text) => Ok(text),
            _ => self.error(ZoneErrorKind::BadEntry),
        }
    }
}

/// Reads the source into a root node.
pub fn read_zone(source: &str, origin: DomainName) -> Result<Node, ZoneError> {
    let mut reader = ZoneReader {
        lexer: Lexer::new(source),
        peeked: None,
        parentheses: 0,
        root: Node::new(),
        origin,
        name: None,
        ttl: None,
        rclass: None,
    };

    loop {
        if reader.lexer.span().end == reader.lexer.source().len() {
            break;
        }

        let is_named_resource =
            matches!(reader.peek(), Some(ZoneToken::String(s)) if !s.starts_with('$'));
        if is_named_resource {
            reader.name = Some(reader.read_name()?);

            // Assert that next token is whitespace, token is later swallowed by the match below.
            match reader.peek() {
                Some(ZoneToken::Whitespace) => {}
                Some(_) => return reader.error(ZoneErrorKind::BadEntry),
                None => return reader.error(ZoneErrorKind::IncompleteEntry),
            }
        }

        match reader.read() {
            Ok(ZoneToken::Whitespace) => handle_resource(&mut reader)?,
            Ok(ZoneToken::String(control)) => handle_control(&mut reader, control)?,
            Ok(_) => return reader.error(ZoneErrorKind::BadEntry),
            Err(err) if *err.kind() == ZoneErrorKind::IncompleteEntry => (),
            Err(err) => return Err(err),
        }

        next_entry(&mut reader, true)?;
    }

    Ok(reader.root)
}

/// Reads zero or more blanks until the end of the entry, then advances to the next entry.
fn next_entry(reader: &mut ZoneReader, fail: bool) -> Result<(), ZoneError> {
    let mut ok = !fail;

    loop {
        if reader.lexer.span().end == reader.lexer.source().len() {
            return Ok(());
        }

        match reader.peek() {
            Some(ZoneToken::Whitespace) if ok => return Ok(()),
            None
            | Some(
                ZoneToken::Whitespace
                | ZoneToken::NewLine
                | ZoneToken::OpenParen
                | ZoneToken::CloseParen,
            ) => match reader.read() {
                Ok(_) => (),
                Err(err) if *err.kind() == ZoneErrorKind::IncompleteEntry => ok = true,
                Err(err) => return Err(err),
            },
            Some(_) if ok => return Ok(()),
            Some(_) => return reader.error(ZoneErrorKind::BadEntry),
        }
    }
}

/// Handles a resource entry. Name is expected to be set by this point.
fn handle_resource(reader: &mut ZoneReader) -> Result<(), ZoneError> {
    let mut defined_ttl = false;
    let mut defined_rclass = false;

    let rtype: RecordType;

    loop {
        if let Ok(ZoneToken::String(string)) = reader.read() {
            match reader.peek() {
                Some(ZoneToken::Whitespace) => _ = reader.read(),
                Some(_) => return reader.error(ZoneErrorKind::BadEntry),
                None => (),
            }

            if let Some(Ok(ttl)) = (!defined_ttl).then(|| string.parse()) {
                defined_ttl = true;
                reader.ttl = Some(ttl);

                continue;
            }

            if let Some(Ok(rclass)) = (!defined_rclass).then(|| string.parse()) {
                defined_rclass = true;
                reader.rclass = Some(rclass);
                continue;
            }

            if let Ok(parsed_rtype) = string.parse() {
                rtype = parsed_rtype;
                break;
            }
        }

        return reader.error(ZoneErrorKind::IncompleteEntry);
    }

    let record = match reader.peek() {
        Some(ZoneToken::String(s)) if s == r"\#" => {
            _ = reader.read();
            reader.read_blank()?;
            let size = reader.read_parsable::<usize>()?;
            let mut buf = vec![0; size];

            let mut data = String::with_capacity(size * 2);
            while let Ok(token) = reader.read() {
                match token {
                    ZoneToken::String(s) => data.push_str(&s),
                    ZoneToken::Whitespace
                    | ZoneToken::NewLine
                    | ZoneToken::OpenParen
                    | ZoneToken::CloseParen => (),
                    _ => return reader.error(ZoneErrorKind::BadEntry),
                }
            }

            if hex::decode_to_slice(data, &mut buf[..]).is_err() {
                return reader.error(ZoneErrorKind::BadEntry);
            }

            match Record::decode_data(
                reader.name.clone().unwrap(),
                reader.ttl.unwrap(),
                reader.rclass.unwrap(),
                rtype,
                size as u16,
                &mut WireRead::new(&buf),
            ) {
                Ok(record) => record,
                Err(_) => return reader.error(ZoneErrorKind::BadEntry),
            }
        }
        _ => Record::decode_zone(
            reader.name.clone().unwrap(),
            reader.ttl.unwrap(),
            reader.rclass.unwrap(),
            rtype,
            reader,
        )?,
    };

    let mut node = &mut reader.root;
    for label in record.name().labels().iter().rev() {
        node = node.insert(label.clone());
    }
    node.add_record(record);

    Ok(())
}

/// Handles a control entry.
fn handle_control(reader: &mut ZoneReader, control: String) -> Result<(), ZoneError> {
    reader.read_whitespace()?;

    match control.as_str() {
        "$ORIGIN" => {
            reader.origin = reader.read_parsable()?;
        }
        "$TTL" => {
            reader.ttl = Some(reader.read_parsable()?);
        }
        _ => return reader.error(ZoneErrorKind::UnknownControl(control)),
    }

    Ok(())
}
