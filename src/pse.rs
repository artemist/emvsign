use crate::exchange::exchange;

#[derive(Debug)]
pub struct PSEEntry {}

pub fn list_applications(card: &pcsc::Card, pse: &str) -> anyhow::Result<Vec<PSEEntry>> {
    let mut is_first = true;
    let mut receive_buffer = [0u8; 256];
    for _ in 0..2 {
        // See EMV 4.3 book 1 chapter 11.3.2
        let p2 = if is_first { 0x00u8 } else { 0x02u8 };
        is_first = false;
        let mut send_buffer = vec![
            0x00,                       // CLA: Interindustry command
            0xa4,                       // INS: SELECT
            0x04,                       // P1: Select by name
            p2,                         // P2: If we're looking for the first element
            pse.as_bytes().len() as u8, // Lc: Length of PSE name
        ];
        send_buffer.extend_from_slice(pse.as_bytes()); // Data: PSE name
        send_buffer.push(0x00); // Le: spec says 0x00
        let (response, sw1, sw2) = exchange(card, &send_buffer)?;

        for b in response {
            print!("{:02x}", b);
        }
        println!("\n{:02x} {:02x}", sw1, sw2)
    }

    Ok(vec![])
}
