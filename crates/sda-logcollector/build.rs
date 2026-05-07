fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("linux")
        && std::env::var("CARGO_FEATURE_LINUX_JOURNAL").is_ok()
    {
        println!("cargo:rustc-link-lib=systemd");
    }
}
