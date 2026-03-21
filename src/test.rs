// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 The zqlu project contributors
macro_rules! str {
    ($name:expr) => {
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/", $name)).trim_end()
    };
}

pub(crate) use str;
