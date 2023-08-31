use anyhow::Context;
use log::debug;

use crate::{
    exchange::{exchange, ADPUCommand},
    tlv::{self, errors::DecodeError, FieldMap, FieldMapExt, Value},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplicationTemplate {
    pub aid: Vec<u8>,
    pub label: String,
    pub priority: Option<u8>,
    pub country: Option<String>,
    pub iin: Option<u32>,
}

impl TryFrom<FieldMap> for ApplicationTemplate {
    type Error = DecodeError;

    fn try_from(mut template: FieldMap) -> Result<Self, Self::Error> {
        let aid = template
            .remove(&0x4f)
            .and_then(|v| v.into_iter().next())
            .and_then(Value::into_binary)
            .ok_or(DecodeError::NoSuchMember(0x4f))?;
        let label = template
            .remove(&0x50)
            .and_then(|v| v.into_iter().next())
            .and_then(Value::into_alphanumeric_special)
            .ok_or(DecodeError::NoSuchMember(0x50))?;
        let priority = template
            .remove(&0x87)
            .and_then(|v| v.into_iter().next())
            .and_then(Value::into_binary)
            .and_then(|v| v.first().cloned());

        let (country, iin) = if let Some(mut inner_map) = template
            .remove(&0x73)
            .and_then(|v| v.into_iter().next())
            .and_then(Value::into_template)
        {
            (
                inner_map
                    .remove(&0x5f55)
                    .and_then(|v| v.into_iter().next())
                    .and_then(Value::into_alphabetic),
                inner_map
                    .remove(&0x42)
                    .and_then(|v| v.into_iter().next())
                    .and_then(Value::into_numeric)
                    .map(|n| n as u32),
            )
        } else {
            (None, None)
        };

        Ok(ApplicationTemplate {
            aid,
            label,
            priority,
            country,
            iin,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PSEData {
    pub languages: Vec<String>,
    pub applications: Vec<ApplicationTemplate>,
}

fn list_from_ppse(pse_map: FieldMap) -> anyhow::Result<Vec<ApplicationTemplate>> {
    let mut fci_data = pse_map
        .into_path(&[0xa5, 0xbf0c])
        .context("Could not find FCI in PPSE")?
        .into_template()
        .unwrap();

    let mut applications = Vec::new();
    for application_map in fci_data
        .remove(&0x61)
        .ok_or_else(|| anyhow::anyhow!("No applications in PPSE"))?
        .into_iter()
    {
        applications.push(application_map.into_template().unwrap().try_into()?);
    }

    Ok(applications)
}

fn list_from_pse(
    card: &mut pcsc::Card,
    pse_map: &FieldMap,
) -> anyhow::Result<Vec<ApplicationTemplate>> {
    let mut applications = Vec::new();

    let sfi = pse_map
        .get_path(&[0xa5, 0x88])
        .context("Could not find SFI in PSE")?
        .as_binary()
        .unwrap()[0];
    if sfi & 0b1110_0000 != 0 {
        anyhow::bail!("Invalid SFI {:02x}", sfi);
    }

    for rec in 1..16 {
        let (sfi_response, sfi_sw) = exchange(card, &ADPUCommand::read_record(sfi, rec))?;
        debug!("SFI {:02x} rec {:02x} ({:04x})", sfi, rec, sfi_sw);
        if sfi_sw == 0x9000 {
            let (_tag, record) = tlv::read_field(&sfi_response).with_context(|| {
                format!("Failed to parse SFI 0x{:02x} record 0x{:02x}", sfi, rec)
            })?;
            debug!("{}", record);
            let record_map = record
                .into_template()
                .ok_or_else(|| anyhow::anyhow!("SFI record wasn't a template!"))?;
            let template = record_map
                .into_path(&[0x61])?
                .into_template()
                .ok_or(DecodeError::WrongType(0x61, "Template"))?;

            applications.push(template.try_into().context("Failed to parse SFI record")?);
        }

        if sfi_sw == 0x6a83 {
            // We've reached the last real record
            break;
        }
    }

    Ok(applications)
}

pub fn list_applications(card: &mut pcsc::Card, ppse: bool) -> anyhow::Result<PSEData> {
    let pse = if ppse {
        "2PAY.SYS.DDF01"
    } else {
        "1PAY.SYS.DDF01"
    };

    let (response, sw) = exchange(card, &ADPUCommand::select(pse.as_bytes()))?;

    if sw != 0x9000 {
        anyhow::bail!(
            "Failure returned by card while selecting PSE {}: 0x{:04x}",
            pse,
            sw
        );
    }

    let (tag, pse_value) = tlv::read_field(&response)
        .context("Failed to parse Payment System Environment response")?;
    debug!("{}:\n{:02x} => {}", pse, tag, pse_value);
    if tag != 0x6f {
        anyhow::bail!("PSE had incorrect root object")
    }

    let pse_map = pse_value
        .into_template()
        .ok_or_else(|| anyhow::anyhow!("PSE root object was not a template"))?;

    Ok(if ppse {
        PSEData {
            languages: Vec::new(),
            applications: list_from_ppse(pse_map)?,
        }
    } else {
        PSEData {
            languages: if let Some(s) = pse_map
                .get_path(&[0xa5, 0x5f2d])
                .ok()
                .and_then(Value::as_alphanumeric)
            {
                s.as_bytes()
                    .chunks_exact(2)
                    .filter_map(|bytes| String::from_utf8(bytes.to_vec()).ok())
                    .collect()
            } else {
                Vec::new()
            },
            applications: list_from_pse(card, &pse_map)?,
        }
    })
}
