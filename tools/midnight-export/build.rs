// Locates the bls_midnight_2p14 parameters bundled in midnight-transient-crypto.
fn main() {
    let home = std::env::var("CARGO_HOME")
        .unwrap_or_else(|_| format!("{}/.cargo", std::env::var("HOME").unwrap()));
    let reg = std::path::Path::new(&home).join("registry/src");
    let mut found = None;
    for idx in std::fs::read_dir(&reg).into_iter().flatten().flatten() {
        let p = idx
            .path()
            .join("midnight-transient-crypto-3.1.0/static/bls_midnight_2p14");
        if p.exists() {
            found = Some(p);
        }
    }
    let p = found.expect("midnight-transient-crypto 3.1.0 sources not found in the cargo registry");
    println!("cargo:rustc-env=MIDNIGHT_2P14={}", p.display());
}
