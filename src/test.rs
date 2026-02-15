macro_rules! str {
    ($name:expr) => {
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/", $name)).trim_end()
    };
}

pub(crate) use str;
