//! Records the polkajam revision this binary was built from.
//!
//! The same-revision rule — the oracle and the node under test built from
//! one checkout — is the whole basis for trusting the oracle's answers, so
//! the binary has to be able to state its own. Read from the manifest so it
//! cannot drift from the dependency it actually compiled.

fn main() {
    let manifest = std::fs::read_to_string("Cargo.toml").unwrap_or_default();
    let rev = manifest
        .lines()
        .find_map(|line| {
            line.split_once("rev = \"")
                .and_then(|(_, rest)| rest.split('"').next())
        })
        .unwrap_or("unknown");
    println!("cargo:rustc-env=ORACLE_POLKAJAM_REV={rev}");
    println!("cargo:rerun-if-changed=Cargo.toml");
}
