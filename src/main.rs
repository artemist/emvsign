use std::collections::HashMap;

use anyhow::Context;
use crypto::chain::IssuerPublicKey;
use log::error;
use structopt::StructOpt;
use tlv::Value;

use crate::crypto::chain::ICCPublicKey;

mod crypto;
mod exchange;
mod processing_options;
mod pse;
mod tlv;
mod transaction;
mod util;

#[derive(Debug, StructOpt)]
struct Options {
    #[structopt(
        short,
        long,
        default_value = "0",
        help = "Reader index, see list-readers"
    )]
    reader: usize,
    #[structopt(
        long,
        help = "Use the PPSE (2PAY.SYS.DDF01) instead of the PSE (1PAY.SYS.DDF01)"
    )]
    ppse: bool,
    #[structopt(subcommand)]
    cmd: Command,
}

#[derive(Debug, StructOpt)]
enum Command {
    #[structopt(about = "List connected readers")]
    ListReaders,
    #[structopt(about = "Show data contained in the PSE")]
    ShowPSE,
    #[structopt(about = "Get the public key")]
    GetKey,
    #[structopt(about = "Run a test transaction")]
    TestTransaction,
}
fn main() -> anyhow::Result<()> {
    pretty_env_logger::init();

    let options = Options::from_args();
    let context =
        pcsc::Context::establish(pcsc::Scope::User).context("Failed to create PCSC session")?;

    let mut state = HashMap::new();

    // Chosen by fair die roll
    state.insert(0x9f37, Value::Binary(vec![0x00, 0x00, 0x00, 0x04]));
    // Currency code: USD
    state.insert(0x5f2a, Value::Numeric(840));

    match options.cmd {
        Command::ListReaders => list_readers(&context),
        Command::ShowPSE => {
            let mut card = get_card(&options, &context).context("Failed to connect to card")?;
            let res = pse::list_applications(&mut card, options.ppse);
            println!("{:#?}", res);
            // Reset the card because we could be in a PIN authenticated state
            if card.disconnect(pcsc::Disposition::ResetCard).is_err() {
                error!("Failed to reset card, you may need to manually unplug the card");
            }
            res?;
            Ok(())
        }
        Command::GetKey => {
            let mut card = get_card(&options, &context).context("Failed to connect to card")?;
            let pse_data = pse::list_applications(&mut card, options.ppse)?;
            let aid = &pse_data
                .applications
                .get(0)
                .ok_or_else(|| anyhow::anyhow!("No applications in PSE"))?
                .aid;

            if aid.len() < 5 {
                anyhow::bail!("AID too short");
            }

            let (options, sda_data) =
                processing_options::read_processing_options(&mut card, aid, &state)?;

            let issuer_key = IssuerPublicKey::from_options(aid[..5].try_into().unwrap(), &options)?;
            println!("{:#?}", issuer_key);
            let icc_key = ICCPublicKey::from_options(&issuer_key, &sda_data, &options)?;
            println!("{:#?}", icc_key);

            // Reset the card because we could be in a PIN authenticated state
            if card.disconnect(pcsc::Disposition::ResetCard).is_err() {
                error!("Failed to reset card, you may need to manually unplug the card");
            }
            Ok(())
        }
        Command::TestTransaction => {
            let mut card = get_card(&options, &context).context("Failed to connect to card")?;
            let pse_data = pse::list_applications(&mut card, options.ppse)?;
            let aid = &pse_data
                .applications
                .get(0)
                .ok_or_else(|| anyhow::anyhow!("No applications in PSE"))?
                .aid;

            let (options, _sda_data) =
                processing_options::read_processing_options(&mut card, aid, &state)?;
            transaction::do_transaction(&mut card, &options, &mut state)?;

            // Reset the card because we could be in a PIN authenticated state
            if card.disconnect(pcsc::Disposition::ResetCard).is_err() {
                error!("Failed to reset card, you may need to manually unplug the card");
            }
            Ok(())
        }
    }
}

fn list_readers(context: &pcsc::Context) -> anyhow::Result<()> {
    let readers = context
        .list_readers_owned()
        .context("Failed to find readers")?;
    for (idx, reader) in readers.iter().enumerate() {
        println!("{}: {:?}", idx, reader)
    }
    Ok(())
}

fn get_card(options: &Options, context: &pcsc::Context) -> anyhow::Result<pcsc::Card> {
    let readers = context
        .list_readers_owned()
        .expect("Failed to list readers");
    let Some(reader) = readers.get(options.reader) else {
        anyhow::bail!(
            "No reader at index {}, only {} readers found",
            options.reader,
            readers.len()
        );
    };
    Ok(context.connect(reader, pcsc::ShareMode::Exclusive, pcsc::Protocols::ANY)?)
}
