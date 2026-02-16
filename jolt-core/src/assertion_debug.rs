use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

static ASSERTION_COUNTER: AtomicUsize = AtomicUsize::new(0);
static ASSERTIONS: Mutex<Vec<(usize, String, String)>> = Mutex::new(Vec::new());

pub fn reset() {
    ASSERTION_COUNTER.store(0, Ordering::SeqCst);
    ASSERTIONS.lock().unwrap().clear();
}

pub fn log_assertion_eq<T: ark_serialize::CanonicalSerialize>(lhs: &T, rhs: &T, label: &str) {
    let idx = ASSERTION_COUNTER.fetch_add(1, Ordering::SeqCst);
    let lhs_str = to_decimal(lhs);
    let rhs_str = to_decimal(rhs);
    eprintln!("[ASSERTION {}] ({}) lhs = {}", idx, label, lhs_str);
    eprintln!("[ASSERTION {}] ({}) rhs = {}", idx, label, rhs_str);
    ASSERTIONS.lock().unwrap().push((idx, lhs_str, rhs_str));
}

pub fn export_json(path: &str) {
    let assertions = ASSERTIONS.lock().unwrap();
    let entries: Vec<String> = assertions
        .iter()
        .map(|(idx, lhs, rhs)| {
            format!(
                "    {{\"index\": {}, \"lhs\": \"{}\", \"rhs\": \"{}\"}}",
                idx, lhs, rhs
            )
        })
        .collect();
    let json = format!(
        "{{\n  \"source\": \"rust_verify_real\",\n  \"assertions\": [\n{}\n  ],\n  \"count\": {}\n}}",
        entries.join(",\n"),
        assertions.len()
    );
    std::fs::write(path, json).expect("Failed to write assertion JSON");
    eprintln!("Exported {} assertions to {}", assertions.len(), path);
}

fn to_decimal<T: ark_serialize::CanonicalSerialize>(val: &T) -> String {
    let mut bytes = Vec::new();
    val.serialize_compressed(&mut bytes).unwrap();
    num_bigint::BigUint::from_bytes_le(&bytes).to_string()
}
