/// Pre-defined size classes for cross-program circuit universality.
///
/// Two programs that fall into the same size class produce structurally identical
/// circuits (same R1CS), so they share a single Groth16 trusted setup (pk, vk).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SizeClass {
    pub name: &'static str,
    pub max_log_t: usize,
    pub max_bytecode_k: usize,
    pub max_ram_k: usize,
    /// Maximum number of u64 words in the program image (bytecode_words).
    /// Derived from max_bytecode_k: each instruction is 4 bytes, so
    /// max_bytecode_k instructions = max_bytecode_k * 4 / 8 = max_bytecode_k / 2 words,
    /// plus 1 for potential alignment.
    pub max_program_words: usize,
}

pub const SIZE_CLASSES: &[SizeClass] = &[
    SizeClass {
        name: "S",
        max_log_t: 14,
        max_bytecode_k: 8192,
        max_ram_k: 8192,
        max_program_words: 8192 / 2 + 1,
    },
    SizeClass {
        name: "M",
        max_log_t: 18,
        max_bytecode_k: 16384,
        max_ram_k: 16384,
        max_program_words: 16384 / 2 + 1,
    },
    SizeClass {
        name: "L",
        max_log_t: 22,
        max_bytecode_k: 32768,
        max_ram_k: 32768,
        max_program_words: 32768 / 2 + 1,
    },
    SizeClass {
        name: "XL",
        max_log_t: 24,
        max_bytecode_k: 65536,
        max_ram_k: 65536,
        max_program_words: 65536 / 2 + 1,
    },
];

/// Returns the smallest size class that fits the given parameters,
/// or None if the proof exceeds all predefined classes.
pub fn find_class(log_t: usize, bytecode_k: usize, ram_k: usize) -> Option<&'static SizeClass> {
    SIZE_CLASSES
        .iter()
        .find(|c| log_t <= c.max_log_t && bytecode_k <= c.max_bytecode_k && ram_k <= c.max_ram_k)
}

/// Returns the smallest size class that fits a program with the given bytecode
/// instruction count and max trace length. Used by the `#[jolt::provable]` macro
/// for automatic class selection -- the user never sees or chooses a class.
///
/// `bytecode_instruction_count` is `bytecode.len()` after `program.decode()`.
/// `max_trace_length` is the value from `#[jolt::provable(max_trace_length = N)]`.
pub fn find_class_for_program(
    bytecode_instruction_count: usize,
    max_trace_length: usize,
) -> Option<&'static SizeClass> {
    let log_t = max_trace_length.next_power_of_two().trailing_zeros() as usize;
    let bytecode_k = bytecode_instruction_count.next_power_of_two();
    SIZE_CLASSES
        .iter()
        .find(|c| log_t <= c.max_log_t && bytecode_k <= c.max_bytecode_k)
}

/// Looks up a size class by name (case-insensitive).
pub fn find_class_by_name(name: &str) -> Option<&'static SizeClass> {
    SIZE_CLASSES
        .iter()
        .find(|c| c.name.eq_ignore_ascii_case(name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_class_smallest() {
        let class = find_class(12, 4096, 4096).unwrap();
        assert_eq!(class.name, "S");
    }

    #[test]
    fn test_find_class_exact_boundary() {
        let class = find_class(14, 8192, 8192).unwrap();
        assert_eq!(class.name, "S");
    }

    #[test]
    fn test_find_class_bumps_to_m() {
        let class = find_class(15, 8192, 8192).unwrap();
        assert_eq!(class.name, "M");
    }

    #[test]
    fn test_find_class_too_large() {
        assert!(find_class(25, 131072, 131072).is_none());
    }

    #[test]
    fn test_find_class_by_name() {
        assert_eq!(find_class_by_name("m").unwrap().name, "M");
        assert_eq!(find_class_by_name("XL").unwrap().name, "XL");
        assert!(find_class_by_name("XXL").is_none());
    }
}
