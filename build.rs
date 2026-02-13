use std::io::Result;

fn main() -> Result<()> {
    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .out_dir("src/api")
        .compile(&["proto/softkms.proto"], &["proto"])?;

    println!("cargo:rerun-if-changed=proto/softkms.proto");
    Ok(())
}
