use anyhow::Context;

use crate::{
    exchange::{exchange, ADPUCommand},
    tlv::{self, errors::DecodeError, Field, Value},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplicationTemplate {
    pub aid: Vec<u8>,
    pub label: String,
    pub priority: Option<u8>,
    pub country: Option<String>,
    pub iin: Option<u32>,
}

impl TryFrom<Field> for ApplicationTemplate {
    type Error = DecodeError;

    fn try_from(value: Field) -> Result<Self, Self::Error> {
        //TODO: Deal with cards like Discover Debit which put multiple Application Templates in one
        //record
        let mut aid = None;
        let mut label = None;
        let mut priority = None;
        let mut country = None;
        let mut iin = None;

        let template = value.get_path_owned(&[0x70, 0x61])?;
        if let Value::Template(fields) = template {
            for field in fields.into_iter() {
                match field.value {
                    Value::Binary(b) if field.tag == 0x4f => aid = Some(b),
                    Value::AlphanumericSpecial(s) if field.tag == 0x50 => label = Some(s),
                    Value::Binary(b) if field.tag == 0x87 && b.len() == 1 => priority = Some(b[0]),
                    Value::Template(ddt) if field.tag == 0x73 => {
                        for ddt_field in ddt.into_iter() {
                            match ddt_field.value {
                                Value::Alphabetic(s) if ddt_field.tag == 0x5f55 => {
                                    country = Some(s)
                                }
                                Value::Numeric(n) if ddt_field.tag == 0x42 => iin = Some(n as u32),
                                _ => {}
                            }
                        }
                    }
                    _ => {}
                }
            }

            Ok(ApplicationTemplate {
                aid: aid.ok_or(DecodeError::NoSuchMember(0x4f))?,
                label: label.ok_or(DecodeError::NoSuchMember(0x50))?,
                priority,
                country,
                iin,
            })
        } else {
            Err(DecodeError::WrongType(0x61, "Template"))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PSEData {
    pub languages: Vec<String>,
    pub applications: Vec<ApplicationTemplate>,
}

pub fn list_applications(card: &mut pcsc::Card, pse: &str) -> anyhow::Result<PSEData> {
    let pse_command = ADPUCommand {
        cla: 0x00,            // Interindustry command
        ins: 0xa4,            // SELECT
        p1: 0x04,             // Select by name
        p2: 0x00,             // 1st element
        data: pse.as_bytes(), // PSE name
        ne: 0x100,            // 256 bytes, the card will correct us
    };
    let (response, sw) = exchange(card, &pse_command)?;

    if sw != 0x9000 {
        anyhow::bail!(
            "Failure returned by card while selecting PSE {}: 0x{:04x}",
            pse,
            sw
        );
    }

    let mut applications = Vec::new();
    let pse_data = tlv::read_field(&response)
        .context("Failed to parse Payment System Environment response")?;
    println!("{}:\n{}", pse, pse_data);

    if let Value::Binary(b) = pse_data
        .get_path(&[0x6f, 0xa5, 0x88])
        .context("Could not find SFI in PSE")?
    {
        let sfi = b[0];
        if sfi & 0b1110_0000 != 0 {
            anyhow::bail!("Invalid SFI {:02x}", sfi);
        }

        for rec in 1..16 {
            let sfi_command = ADPUCommand {
                cla: 0x00,             // Interindustry command
                ins: 0xb2,             // READ RECORD
                p1: rec,               // Record number
                p2: (sfi << 3) | 0x04, // SFI, P1 is a record number
                data: &[],             // No data
                ne: 0x100,             // 256 bytes, the card will correct us
            };
            let (sfi_response, sfi_sw) = exchange(card, &sfi_command)?;
            println!("SFI {:02x} rec {:02x} ({:04x})", b[0], rec, sfi_sw);
            if sfi_sw == 0x9000 {
                let record = tlv::read_field(&sfi_response).with_context(|| {
                    format!("Failed to parse SFI 0x{:02x} record 0x{:02x}", sfi, rec)
                })?;
                println!("{}", record);

                applications.push(record.try_into().context("Failed to parse SFI record")?);
            }

            if sfi_sw == 0x6a83 {
                // We've reached the last real record
                break;
            }
        }
    }

    Ok(PSEData {
        languages: if let Ok(s) = pse_data.get_path_string(&[0x6f, 0xa5, 0x5f2d]) {
            s.as_bytes()
                .chunks_exact(2)
                .filter_map(|bytes| String::from_utf8(bytes.to_vec()).ok())
                .collect()
        } else {
            Vec::new()
        },
        applications,
    })
}
