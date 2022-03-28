use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt]
struct Options {
    #[structopt(short, long, default_value = 0)]
    reader: u32,
}
fn main() -> anyhow::Result<()> {
    let context = pcsc::Context::establish(pcsc::Scope::User)?;
    let readers = context.list_readers_owned()?;
    for reader in readers {
        println!("Found reader {:?}", reader)
    }
}
