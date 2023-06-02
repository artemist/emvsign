use crate::exchange::{exchange, ADPUCommand};

pub fn print_dol(card: &mut pcsc::Card, aid: &[u8]) -> anyhow::Result<()> {
    let select_command = ADPUCommand {
        cla: 0x00,
        ins: 0xa4,
        p1: 0x04,
        p2: 0x00,
        data: aid,
        ne: 0x100,
    };
    let (response, sw) = exchange(card, &select_command)?;
    if sw != 0x9000 {
        anyhow::bail!(
            "Failure returned by card while selecting payment app: 0x{:04x}",
            sw
        );
    }

    for b in &response {
        print!("{:02x}", b);
    }

    Ok(())
}
