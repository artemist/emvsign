use anyhow::Context;
use structopt::StructOpt;
mod exchange;
mod pse;
mod tlv;

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
        default_value = "1PAY.SYS.DDF01",
        help = "Directory Definition File which contains the Payment System Directory"
    )]
    // Technically this should be a Box<[u8]> but structopt demands that everything be valid UTF-8
    pse: String,
    #[structopt(subcommand)]
    cmd: Command,
}

#[derive(Debug, StructOpt)]
enum Command {
    #[structopt(about = "List connected readers")]
    ListReaders,
    #[structopt(about = "Get the public key")]
    GetKey,
    #[structopt(about = "Show data contained in the PSE")]
    ShowPSE,
}
fn main() -> anyhow::Result<()> {
    let options = Options::from_args();
    let context =
        pcsc::Context::establish(pcsc::Scope::User).context("Failed to create PCSC session")?;

    match options.cmd {
        Command::ListReaders => list_readers(&context),
        Command::ShowPSE => {
            let mut card = get_card(&options, &context).context("Failed to connect to card")?;
            let res = pse::list_applications(&mut card, &options.pse);
            println!("{:#?}", res);
            // Reset the card because we could be in a PIN authenticated state
            if card.disconnect(pcsc::Disposition::ResetCard).is_err() {
                eprintln!("Failed to reset card, you may need to manually unplug the card");
            }
            res?;
            Ok(())
        }
        Command::GetKey => unimplemented!(),
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
    if options.reader >= readers.len() {
        anyhow::bail!(
            "No reader at index {}, only {} readers found",
            options.reader,
            readers.len()
        );
    }
    Ok(context.connect(
        &readers[options.reader],
        pcsc::ShareMode::Exclusive,
        pcsc::Protocols::ANY,
    )?)
}
