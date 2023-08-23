use anyhow::Context;
use log::{debug, info};

use crate::{
    exchange::{exchange, ADPUCommand},
    tlv,
};

pub fn read_processing_options(card: &mut pcsc::Card, aid: &[u8]) -> anyhow::Result<tlv::Value> {
    let (response, sw) = exchange(card, &ADPUCommand::select(aid))?;
    if sw != 0x9000 {
        anyhow::bail!(
            "Failure returned by card while selecting payment app: 0x{:04x}",
            sw
        );
    }

    info!(
        "selected payment application {:02x?}\n{}",
        aid,
        tlv::read_field(&response)?
    );

    // Request command template, no length, as recommended by EMV 4.3 book 3 section 10.1
    // TODO: Handle the case where a PDOL is in the FCI. I have one card that does this but
    // it would be annoying to implement
    let (response, sw) = exchange(card, &ADPUCommand::get_processing_options(&[0x83, 0x00]))?;
    if sw != 0x9000 {
        anyhow::bail!(
            "Failure returned by card while doing empty get processing options: 0x{:04x}",
            sw
        );
    }

    let gpo = tlv::read_field(&response).context("Failed to parse processing options")?;
    debug!("{}", gpo);

    let (_aip, afl) = match gpo.tag {
        0x77 => (
            gpo.get_path_binary(&[0x77, 0x82])
                .context("Failed to read AIP")?,
            gpo.get_path_binary(&[0x77, 0x94])
                .context("Failed to read AFL")?,
        ),
        0x80 => {
            let resp = gpo.get_path_binary(&[0x80])?;
            if resp.len() < 6 {
                anyhow::bail!("Failed to read AIP and AFL!");
            }
            resp.split_at(2)
        }
        tag => {
            anyhow::bail!("Got tag {:04x} when trying to read AIP and AFL", tag);
        }
    };
    let mut card_info = Vec::new();
    for afl_fields in afl.chunks_exact(4) {
        let sfi = afl_fields[0] >> 3;
        let first_record = afl_fields[1];
        let last_record = afl_fields[2];

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
            let field = tlv::read_field(&response)?;
            debug!("SFI {:02x} rec {:02x} ({:04x})\n{}", sfi, record, sw, field);
            card_info.extend_from_slice(field.value.get_template().ok_or_else(|| {
                anyhow::anyhow!("SFI {:02x} record {:02x} is not a template", sfi, record)
            })?);
        }
    }

    let ret = tlv::Value::Template(card_info);
    debug!("{}", ret);
    Ok(ret)
}
