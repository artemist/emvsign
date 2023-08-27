use std::collections::HashMap;

use anyhow::Context;
use log::debug;

use crate::{
    exchange::{exchange, ADPUCommand},
    tlv::{self, FieldMap, Value},
};

pub fn do_transaction(
    card: &mut pcsc::Card,
    options: &FieldMap,
    state: &mut HashMap<u16, Value>,
) -> anyhow::Result<()> {
    let ddol = options
        .get(&0x9f49)
        .and_then(Value::as_dol)
        .ok_or_else(|| anyhow::anyhow!("Could not get ddol"))?;
    let (authenticate_resp_bytes, sw) = exchange(
        card,
        &ADPUCommand::internal_authenticate(&ddol.encode(state)),
    )?;
    let (tag, value) = tlv::read_field(&authenticate_resp_bytes)
        .context("Failed to parse internal authenticate")?;

    let sdad = match tag {
        0x77 => value.get_path(&[0x9f4b]).ok().and_then(Value::as_binary),
        0x80 => value.as_binary(),
        _tag => None,
    }
    .ok_or_else(|| anyhow::anyhow!("Failed to get Signed Dynamic Authentication Data"))?;

    debug!("{}, {:04x}", hex::encode(sdad), sw);

    Ok(())
}
