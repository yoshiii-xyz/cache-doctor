#![no_main]

use cache_doctor::{explain_report, CacheReport};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let input = String::from_utf8_lossy(data);
    if let Ok(report) = serde_json::from_str::<CacheReport>(&input) {
        let _ = explain_report(&report);
    }
});
