#![cfg_attr(feature = "guest", no_std)]

// RSA-2048 signature verification in zero-knowledge.
//
// Checks that sig^65537 mod n == expected using Montgomery multiplication.
// All 2048-bit integers are represented as little-endian arrays of 32 × u64 limbs.

const N: usize = 32;

#[jolt::provable(heap_size = 65536, max_trace_length = 4194304)]
fn rsa_verify(n: [u64; 32], sig: [u64; 32], expected: [u64; 32]) -> bool {
    let result = mod_exp_65537(&sig, &n);
    result == expected
}

fn cmp_ge(a: &[u64; N], b: &[u64; N]) -> bool {
    let mut i = N;
    while i > 0 {
        i -= 1;
        if a[i] > b[i] {
            return true;
        }
        if a[i] < b[i] {
            return false;
        }
    }
    true // equal
}

fn sub_assign(a: &mut [u64; N], b: &[u64; N]) {
    let mut borrow: u64 = 0;
    let mut i = 0;
    while i < N {
        let (x1, o1) = a[i].overflowing_sub(b[i]);
        let (x2, o2) = x1.overflowing_sub(borrow);
        a[i] = x2;
        borrow = (o1 as u64) + (o2 as u64);
        i += 1;
    }
}

// Returns n_inv such that n[0] * n_inv ≡ -1 (mod 2^64).
// Requires n[0] to be odd (always true for RSA moduli).
fn compute_n_inv(n0: u64) -> u64 {
    // Newton iteration: x_{k+1} = x_k * (2 - n0 * x_k) mod 2^{2^{k+1}}
    // 6 iterations reach 2^64 precision.
    let mut x = 1u64;
    let mut k = 0;
    while k < 6 {
        x = x.wrapping_mul(2u64.wrapping_sub(n0.wrapping_mul(x)));
        k += 1;
    }
    x.wrapping_neg() // n_inv = -(n0^{-1}) mod 2^64
}

// Computes R^2 mod n where R = 2^(64*N) = 2^2048.
// Uses 4096 successive doublings mod n.
fn compute_r2(n: &[u64; N]) -> [u64; N] {
    let mut x = [0u64; N];
    x[0] = 1;

    let mut iter = 0;
    while iter < 4096 {
        let overflow = (x[N - 1] >> 63) != 0;

        let mut carry = 0u64;
        let mut j = 0;
        while j < N {
            let new_carry = x[j] >> 63;
            x[j] = (x[j] << 1) | carry;
            carry = new_carry;
            j += 1;
        }

        // If 2*x overflowed 2048 bits, or 2*x >= n, subtract n
        if overflow || cmp_ge(&x, n) {
            sub_assign(&mut x, n);
        }

        iter += 1;
    }

    x
}

// Montgomery multiplication (CIOS): returns a * b * R^{-1} mod n.
// n_inv must satisfy n[0] * n_inv ≡ -1 (mod 2^64).
fn mont_mul(a: &[u64; N], b: &[u64; N], n: &[u64; N], n_inv: u64) -> [u64; N] {
    let mut t = [0u64; N];
    // t_high accumulates overflow beyond the N-th limb.
    // Fits comfortably in u128 (at most ~2^65 per iteration).
    let mut t_high: u128 = 0;

    let mut i = 0;
    while i < N {
        let ai = a[i];

        let mut carry: u64 = 0;
        let mut j = 0;
        while j < N {
            let x: u128 = ai as u128 * b[j] as u128 + t[j] as u128 + carry as u128;
            t[j] = x as u64;
            carry = (x >> 64) as u64;
            j += 1;
        }
        t_high += carry as u128;

        // m is chosen so that t[0] + m * n[0] ≡ 0 (mod 2^64),
        // guaranteeing t[0] == 0 after the next accumulation (the Montgomery invariant).
        let m: u64 = t[0].wrapping_mul(n_inv);

        carry = 0;
        j = 0;
        while j < N {
            let x: u128 = m as u128 * n[j] as u128 + t[j] as u128 + carry as u128;
            t[j] = x as u64;
            carry = (x >> 64) as u64;
            j += 1;
        }
        t_high += carry as u128;

        // t[0] == 0 after step 3 (Montgomery invariant); discard it by right-shifting one limb.
        j = 0;
        while j < N - 1 {
            t[j] = t[j + 1];
            j += 1;
        }
        t[N - 1] = t_high as u64; // low 64 bits of overflow
        t_high >>= 64; // keep only the high bit (0 or 1)

        i += 1;
    }

    // Conditional subtraction: result must be in [0, n).
    if t_high > 0 || cmp_ge(&t, n) {
        sub_assign(&mut t, n);
    }

    t
}

// Computes base^65537 mod n using Montgomery multiplication.
// 65537 = 0x10001 = 2^16 + 1 (17 bits: 1, followed by 15 zeros, then 1).
fn mod_exp_65537(base: &[u64; N], n: &[u64; N]) -> [u64; N] {
    let n_inv = compute_n_inv(n[0]);
    let r2 = compute_r2(n);

    let mut one = [0u64; N];
    one[0] = 1;

    // Convert base to Montgomery form: base_m = base * R mod n
    let base_m = mont_mul(base, &r2, n, n_inv);

    // 1 in Montgomery form: one_m = 1 * R mod n
    let one_m = mont_mul(&one, &r2, n, n_inv);

    // Left-to-right square-and-multiply over the 17 bits of 65537.
    // Start accumulator at 1 (in Montgomery form).
    let mut acc = one_m;

    // bit 16 = 1 (MSB)
    acc = mont_mul(&acc, &acc, n, n_inv);
    acc = mont_mul(&acc, &base_m, n, n_inv);

    // bits 15 down to 1 are all 0 — only square
    let mut bit = 15u32;
    while bit >= 1 {
        acc = mont_mul(&acc, &acc, n, n_inv);
        bit -= 1;
    }

    // bit 0 = 1 — square then multiply
    acc = mont_mul(&acc, &acc, n, n_inv);
    acc = mont_mul(&acc, &base_m, n, n_inv);

    // Convert from Montgomery form back to standard: result = acc * R^{-1} mod n
    mont_mul(&acc, &one, n, n_inv)
}
