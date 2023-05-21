use anyhow::Context;

pub fn exchange(card: &pcsc::Card, command: &[u8]) -> anyhow::Result<(Vec<u8>, u8, u8)> {
    let mut recieve_buffer = [0u8; 256];
    let mut response = Vec::new();
    let mut sw1 = 0u8;
    let mut sw2 = 0u8;
    {
        let data = card
            .transmit(&command, &mut recieve_buffer)
            .context("Failed to recieve from card")?;
        if data.len() < 2 {
            anyhow::bail!("Received message too short");
        }
        sw1 = data[data.len() - 2];
        sw2 = data[data.len() - 1];
        response.extend_from_slice(&data[..(data.len() - 2)]);
    }

    if sw1 == 0x6c {
        // Reduce data size requested
        let mut modified_command = Vec::with_capacity(command.len());
        modified_command.extend_from_slice(command);
        modified_command[4] = sw2; // Override expected length

        let data = card
            .transmit(&command, &mut recieve_buffer)
            .context("Failed to recieve from card after reducing size")?;
        sw1 = data[data.len() - 2];
        sw2 = data[data.len() - 1];
        response.extend_from_slice(&data[..(data.len() - 2)]);
    }

    while sw1 == 0x61 {
        // Continuation data available
        let continuation_command = [
            0x00, // CLA: Interindustry command
            0xc0, // INS: GET RESPONSE
            0x00, // P1: N/A
            0x00, // P2: N/A
            sw2,  // P3: Expected length
        ];

        let data = card
            .transmit(&continuation_command, &mut recieve_buffer)
            .context("Failed to recieve from card while requesting continuation data")?;
        sw1 = data[data.len() - 2];
        sw2 = data[data.len() - 1];
        response.extend_from_slice(&data[..(data.len() - 2)]);
    }

    Ok((response, sw1, sw2))
}
