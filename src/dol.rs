use anyhow::Context;

use crate::{
    exchange::{exchange, ADPUCommand},
    tlv,
};

pub fn print_dol(card: &mut pcsc::Card, aid: &[u8]) -> anyhow::Result<()> {
    let (response, sw) = exchange(card, &ADPUCommand::select(aid))?;
    if sw != 0x9000 {
        anyhow::bail!(
            "Failure returned by card while selecting payment app: 0x{:04x}",
            sw
        );
    }

    let fci = tlv::read_field(&response).context("Failed to parse FCI")?;
    println!("{}", fci);

    let (response, sw) = exchange(card, &ADPUCommand::read_record(1, 1))?;
    if sw != 0x9000 {
        anyhow::bail!(
            "Failure returned by card while reading record: 0x{:04x}",
            sw
        );
    }

    let fci = tlv::read_field(&response).context("Failed to parse FCI")?;
    println!("{}", fci);

    Ok(())
}
