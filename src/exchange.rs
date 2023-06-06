use anyhow::Context;

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub struct ADPUCommand<'a> {
    /// Command class
    pub cla: u8,
    /// Command instruction
    pub ins: u8,
    /// First byte of command paramenter
    pub p1: u8,
    /// Second byte of command parameter
    pub p2: u8,
    /// Command data
    pub data: &'a [u8],
    /// Number of bytes expected for response, between 0 and 65536 inclusive
    pub ne: u32,
}

impl ADPUCommand<'_> {
    pub fn encode(&self) -> Option<Box<[u8]>> {
        let mut raw = Vec::with_capacity(10 + self.data.len());
        raw.extend_from_slice(&[self.cla, self.ins, self.p1, self.p2]);

        let nc = self.data.len();
        if nc == 0 {
            // Do nothing, Lc is empty
        } else if nc <= 255 {
            raw.push(nc as u8);
        } else if nc <= 65535 {
            raw.push(0u8);
            raw.extend_from_slice(&(nc as u16).to_be_bytes());
        } else {
            // Impossible to encode over 65536 bytes
            return None;
        }
        raw.extend_from_slice(self.data);

        if self.ne == 0 {
            // Do nothing, Le is empty
        } else if self.ne <= 256 {
            // 256 will be 0x100 which we truncate to 0x00. This is correct.
            raw.push(self.ne as u8);
        } else if self.ne <= 65536 {
            // 65536 will be 0x10000 which we truncate to 0x0000. This is correct.
            if nc <= 255 {
                raw.push(0u8);
            }
            raw.extend_from_slice(&(self.ne as u16).to_be_bytes());
        }

        Some(raw.into_boxed_slice())
    }

    pub fn select(aid: &[u8]) -> ADPUCommand {
        ADPUCommand {
            cla: 0x00, // Interindustry command
            ins: 0xa4, // SELECT
            p1: 0x04,  // Select by name
            p2: 0x00,  // 1st element
            data: aid, // AID
            ne: 0x100, // 256 bytes, the card will correct us
        }
    }

    pub fn read_record(sfi: u8, record: u8) -> ADPUCommand<'static> {
        ADPUCommand {
            cla: 0x00,             // Interindustry command
            ins: 0xb2,             // READ RECORD
            p1: record,            // Record number
            p2: (sfi << 3) | 0x04, // SFI, P1 is a record number
            data: &[],             // No data
            ne: 0x100,             // 256 bytes, the card will correct us
        }
    }

    pub fn get_processing_options(pdol: &[u8]) -> ADPUCommand {
        ADPUCommand {
            cla: 0x80,  // Propriatery command
            ins: 0xa8,  // GET PROCESSING OPTIONS
            p1: 0x00,   // The only non-RFU value
            p2: 0x00,   // The only non-RFU value
            data: pdol, // Processing Data Object List, may be empty
            ne: 0x100,  // 256 bytes, the card will correct us
        }
    }
}

pub fn exchange(card: &mut pcsc::Card, command: &ADPUCommand) -> anyhow::Result<(Vec<u8>, u16)> {
    let mut recieve_buffer = [0u8; 256];
    let mut response = Vec::new();
    let mut sw1;
    let mut sw2;
    let tx = card.transaction().context("Failed to create transaction")?;
    {
        let data = tx
            .transmit(
                &command
                    .encode()
                    .ok_or_else(|| anyhow::anyhow!("Could not encode command"))?,
                &mut recieve_buffer,
            )
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
        let mut modified_command = *command;
        modified_command.ne = sw2 as u32;

        let data = tx
            .transmit(
                &modified_command
                    .encode()
                    .ok_or_else(|| anyhow::anyhow!("Could not encode command"))?,
                &mut recieve_buffer,
            )
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

        let data = tx
            .transmit(&continuation_command, &mut recieve_buffer)
            .context("Failed to recieve from card while requesting continuation data")?;
        sw1 = data[data.len() - 2];
        sw2 = data[data.len() - 1];
        response.extend_from_slice(&data[..(data.len() - 2)]);
    }

    Ok((response, (sw1 as u16) << 8 | (sw2 as u16)))
}
