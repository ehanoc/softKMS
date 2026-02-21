use std::io::Result;
use std::path::Path;

fn main() -> Result<()> {
    // Always regenerate proto code to pick up changes
    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .out_dir("src/api")
        .compile(&["proto/softkms.proto"], &["proto"])?;

    println!("cargo:rerun-if-changed=proto/softkms.proto");

    // Compile Falcon C library
    compile_falcon();

    println!("cargo:rerun-if-changed=libs/falcon/");
    Ok(())
}

fn compile_falcon() {
    let falcon_path = Path::new("libs/falcon");

    cc::Build::new()
        .include(falcon_path)
        .define("FALCON_FPNATIVE", Some("1"))
        .define("FALCON_DET", Some("1"))
        .file(falcon_path.join("codec.c"))
        .file(falcon_path.join("common.c"))
        .file(falcon_path.join("deterministic.c"))
        .file(falcon_path.join("falcon.c"))
        .file(falcon_path.join("fft.c"))
        .file(falcon_path.join("fpr.c"))
        .file(falcon_path.join("keygen.c"))
        .file(falcon_path.join("rng.c"))
        .file(falcon_path.join("shake.c"))
        .file(falcon_path.join("sign.c"))
        .file(falcon_path.join("vrfy.c"))
        .compile("falcon");
}
