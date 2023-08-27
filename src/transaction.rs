use std::collections::HashMap;

use anyhow::Context;
use log::debug;

use crate::{
    exchange::{exchange, ADPUCommand},
    tlv::{self, Value},
};

pub fn do_transaction(
    card: &mut pcsc::Card,
    options: &Value,
    state: &mut HashMap<u16, Value>,
) -> anyhow::Result<()> {
    let ddol = options.get_dol(0x9f49)?;
    let (authenticate_resp_bytes, sw) = exchange(
        card,
        &ADPUCommand::internal_authenticate(&ddol.encode(state)),
    )?;
    let authenticate_resp = tlv::read_field(&authenticate_resp_bytes)
        .context("Failed to parse internal authenticate")?;

    let sdad = match authenticate_resp.tag {
        0x77 => authenticate_resp
            .get_path_binary(&[0x77, 0x9f4b])
            .context("Failed to read Signed Dynamic Authentication Data")?,
        0x80 => authenticate_resp.get_path_binary(&[0x80])?,
        tag => {
            anyhow::bail!(
                "Got tag {:04x} when trying to read Signed Dynamic Authentication Data",
                tag
            );
        }
    };

    debug!("{}, {:04x}", hex::encode(sdad), sw);

    Ok(())
}
