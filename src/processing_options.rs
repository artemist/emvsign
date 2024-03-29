use anyhow::Context;
use log::{debug, info};

use crate::{
    exchange::{exchange, ADPUCommand},
    tlv::{self, DecodeError, FieldMap, FieldMapExt, OptionsMap, Value},
};

pub fn read_processing_options(
    card: &mut pcsc::Card,
    aid: &[u8],
    state: &OptionsMap,
) -> anyhow::Result<(FieldMap, Vec<u8>)> {
    let (ats, sw) = exchange(card, &ADPUCommand::select(aid))?;
    if sw != 0x9000 {
        anyhow::bail!(
            "Failure returned by card while selecting payment app: 0x{:04x}",
            sw
        );
    }

    let (ats_tag, ats_value) = tlv::read_field(&ats)?;
    info!(
        "selected payment application {:02x?}\n{:04x} => {}",
        aid, ats_tag, ats_value
    );

    let ats_map = ats_value
        .as_template()
        .ok_or_else(|| anyhow::anyhow!("ATS response was not a map!"))?;

    let pdol_encoded = ats_map
        .get_path(&[0xa5, 0x9f38])
        .ok()
        .and_then(Value::as_dol)
        .map(|pdol| pdol.encode(Some(0x83), state))
        .unwrap_or(vec![0x83, 0x00]);

    // Request command template, no length, as recommended by EMV 4.3 book 3 section 10.1
    let (response, sw) = exchange(card, &ADPUCommand::get_processing_options(&pdol_encoded))?;
    if sw != 0x9000 {
        anyhow::bail!(
            "Failure returned by card while running GET PROCESSING OPTIONS with {}: 0x{:04x}",
            hex::encode(pdol_encoded),
            sw
        );
    }

    let (gpo_tag, gpo_value) =
        tlv::read_field(&response).context("Failed to parse processing options")?;
    debug!("{} => {}", gpo_tag, gpo_value);

    let (aip, afl) = match gpo_tag {
        0x77 => (
            gpo_value
                .get_path_binary(&[0x82])
                .context("Failed to read AIP")?,
            gpo_value
                .get_path_binary(&[0x94])
                .context("Failed to read AFL")?,
        ),
        0x80 => {
            let resp = gpo_value
                .as_binary()
                .ok_or(DecodeError::WrongType(0x80, "Binary"))?;
            if resp.len() < 6 {
                anyhow::bail!("Failed to read AIP and AFL!");
            }
            resp.split_at(2)
        }
        tag => {
            anyhow::bail!("Got tag {:04x} when trying to read AIP and AFL", tag);
        }
    };
    let mut card_info = FieldMap::new();
    card_info.insert(0x82, Value::Binary(aip.to_vec()));
    card_info.insert(0x94, Value::Binary(afl.to_vec()));

    let mut sda_data = Vec::new();
    for afl_fields in afl.chunks_exact(4) {
        let sfi = afl_fields[0] >> 3;
        let first_record = afl_fields[1];
        let last_record = afl_fields[2];
        let num_sda = afl_fields[3];

        for record in first_record..=last_record {
            let (response, sw) = exchange(card, &ADPUCommand::read_record(sfi, record))?;
            if sw != 0x9000 {
                anyhow::bail!(
                    "Failure returned by card while reading sfi {:02x} record {:02x}: 0x{:04x}",
                    sfi,
                    record,
                    sw
                );
            }
            let (file_tag, file_value) = tlv::read_field(&response)?;
            debug!(
                "SFI {:02x} rec {:02x} ({:04x})\n{} => {}",
                sfi, record, sw, file_tag, file_value
            );
            card_info.extend(file_value.into_template().ok_or_else(|| {
                anyhow::anyhow!("SFI {:02x} record {:02x} is not a template", sfi, record)
            })?);

            if record - first_record < num_sda {
                debug!("Adding record {:02x}", record);
                // Exclude the tag and length if SFI is 1-10. (Book 3 section 10.3)
                // What the fuck.
                if sfi <= 10 {
                    let (_, _, tl_len) = tlv::decoders::read_tl(&response)?;
                    sda_data.extend(&response[tl_len..])
                } else if sfi <= 30 {
                    sda_data.extend(&response)
                }
            }
        }
    }

    debug!("{}", card_info.display());
    Ok((card_info, sda_data))
}
