use crate::{exchange::exchange, tlv::{TLVValue, self}};

#[derive(Debug)]
pub struct PSEEntry {}

pub fn list_applications(card: &mut pcsc::Card, pse: &str) -> anyhow::Result<Vec<PSEEntry>> {
    // Read the PSE
    let mut send_buffer = vec![
        0x00,                       // CLA: Interindustry command
        0xa4,                       // INS: SELECT
        0x04,                       // P1: Select by name
        0x00,                       // P2: We're looking for the first element
        pse.as_bytes().len() as u8, // Lc: Length of PSE name
    ];
    send_buffer.extend_from_slice(pse.as_bytes()); // Data: PSE name
    send_buffer.push(0x00); // Le: spec says 0x00
    let (response, _sw) = exchange(card, &send_buffer)?;

    let pse_data = tlv::read_field(&response)?;
    println!("{}:\n{}", pse, pse_data);

    if let TLVValue::Binary(b) = pse_data.get_path(&[0x6f, 0xa5, 0x88]).unwrap() {
        let sfi = b[0];
        if sfi & 0b1110_0000 != 0 {
            anyhow::bail!("Invalid SFI {:02x}", sfi);
        }
        for rec in 1..16 {
            let sfi_send_buffer = vec![
                0x00,               // CLA: Interindustry command
                0xb2,               // INS: READ RECORD
                rec,                // P1: Record number
                0x04 | (b[0] << 3), // P2: SFI, P1 is a record number
                0x28,
            ];
            let (sfi_response, sfi_sw) = exchange(card, &sfi_send_buffer)?;
            println!("SFI {:02x} rec {:02x} ({:04x})", b[0], rec, sfi_sw);
            if sfi_sw == 0x9000 {
                println!("{}", tlv::read_field(&sfi_response)?);
            }

            if sfi_sw == 0x6a83 {
                // We've reached the last real record
                break;
            }
        }
    }

    Ok(vec![])
}
