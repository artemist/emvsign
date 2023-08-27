use std::{cmp::min, collections::HashMap, fmt::Display};

use super::{decoders::read_tl, DecodeError, Value};

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct DOLEntry {
    pub tag: u16,
    pub size: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dol {
    entries: Vec<DOLEntry>,
    size: usize,
}

impl Dol {
    pub fn new_from_entries(entries: Vec<DOLEntry>) -> Self {
        let size = entries.iter().map(|entry| &entry.size).sum();
        Dol { entries, size }
    }

    pub fn get_size(&self) -> usize {
        self.size
    }

    pub fn get_entries(&self) -> &[DOLEntry] {
        &self.entries
    }

    pub fn encode(&self, data: &HashMap<u16, Value>) -> Box<[u8]> {
        let mut encoded = vec![0; self.size];
        let mut encoded_slice = encoded.as_mut_slice();
        for entry in &self.entries {
            let (dest, remaining) = encoded_slice.split_at_mut(entry.size);
            if let Some(value) = data.get(&entry.tag) {
                match value {
                    Value::Alphabetic(s) => Self::copy_bytes(s.as_bytes(), dest),
                    Value::Alphanumeric(s) => Self::copy_bytes(s.as_bytes(), dest),
                    Value::AlphanumericSpecial(s) => Self::copy_bytes(s.as_bytes(), dest),
                    Value::Binary(b) => Self::copy_bytes(b, dest),
                    Value::DigitString(s) => {
                        dest.fill(0xff);
                        for (digits, dest) in s.chunks(2).zip(dest.iter_mut()) {
                            *dest = match digits {
                                [single] => single << 4 | 0x0f,
                                [higher, lower] => higher << 4 | lower,
                                [..] => unreachable!(), // slice::chunks(2) cannot return any other sizes
                            }
                        }
                    }
                    Value::Numeric(mut number) => {
                        for dest in dest.iter_mut().rev() {
                            let digits: u8 = (number % 100).try_into().unwrap();
                            number /= 100;

                            *dest = (digits / 10) << 4 | (digits % 10);
                        }
                    }
                    // Templates should just be all zeroes
                    Value::Template(_) => {}
                    // Technically this would be binary to the card but it should never ask
                    Value::Dol(_) => {}
                }
            }
            encoded_slice = remaining;
            // If we don't know the element it has to be zeroed, but it already is
        }

        encoded.into_boxed_slice()
    }

    fn copy_bytes(b: &[u8], out: &mut [u8]) {
        let copied_len = min(b.len(), out.len());
        out[..copied_len].copy_from_slice(b);
    }
}

impl TryFrom<&[u8]> for Dol {
    type Error = DecodeError;

    fn try_from(mut value: &[u8]) -> Result<Self, Self::Error> {
        let mut entries = Vec::new();
        let mut total_len = 0;
        while !value.is_empty() {
            let (tag, size, tl_len) = read_tl(value)?;
            entries.push(DOLEntry { tag, size });
            value = &value[tl_len..];
            total_len += size;
        }

        Ok(Dol {
            entries,
            size: total_len,
        })
    }
}

impl Display for DOLEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let tag_name = super::elements::ELEMENTS
            .get(&self.tag)
            .map_or("", |elem| elem.name);
        write!(
            f,
            "0x{:04x} (\"{}\") 0x{:x} bytes",
            self.tag, tag_name, self.size
        )
    }
}
