//! Curve traits for Jolt's cryptographic operations.
//!
//! This module defines the `JoltCurve` trait which abstracts over pairing-friendly
//! elliptic curves used for polynomial commitments and zero-knowledge proofs.

use crate::field::JoltField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use std::fmt::Debug;
use std::ops::{Add, AddAssign, Mul, Neg, Sub, SubAssign};

/// A group element suitable for cryptographic operations.
///
/// This trait abstracts over elliptic curve group operations needed for
/// Pedersen commitments, polynomial commitments, and other cryptographic primitives.
pub trait JoltGroupElement:
    Clone
    + Copy
    + Debug
    + Default
    + Eq
    + Send
    + Sync
    + 'static
    + Add<Output = Self>
    + Sub<Output = Self>
    + Neg<Output = Self>
    + for<'a> Add<&'a Self, Output = Self>
    + for<'a> Sub<&'a Self, Output = Self>
    + AddAssign
    + SubAssign
    + CanonicalSerialize
    + CanonicalDeserialize
{
    fn zero() -> Self;

    fn is_zero(&self) -> bool;

    fn double(&self) -> Self;

    fn scalar_mul<F: JoltField>(&self, scalar: &F) -> Self;
}

/// A pairing-friendly curve suitable for Dory PCS and ZK operations.
///
/// The scalar field is passed as a generic parameter to functions rather than
/// being an associated type, allowing flexibility in which field is used with
/// the curve operations.
pub trait JoltCurve: Clone + Sync + Send + 'static {
    /// G1 group element type
    type G1: JoltGroupElement;

    /// G2 group element type
    type G2: JoltGroupElement;

    /// Target group element type (result of pairing)
    type GT: Clone
        + Debug
        + Default
        + Eq
        + Send
        + Sync
        + 'static
        + Add<Output = Self::GT>
        + for<'a> Add<&'a Self::GT, Output = Self::GT>
        + AddAssign
        + CanonicalSerialize
        + CanonicalDeserialize;

    /// Returns the generator of G1
    fn g1_generator() -> Self::G1;

    /// Returns the generator of G2
    fn g2_generator() -> Self::G2;

    /// Compute pairing e(g1, g2)
    fn pairing(g1: &Self::G1, g2: &Self::G2) -> Self::GT;

    /// Multi-pairing: ∏ᵢ e(g1s[i], g2s[i])
    fn multi_pairing(g1s: &[Self::G1], g2s: &[Self::G2]) -> Self::GT;

    /// Multi-scalar multiplication in G1: Σᵢ scalars[i] * bases[i]
    fn g1_msm<F: JoltField>(bases: &[Self::G1], scalars: &[F]) -> Self::G1;

    /// Multi-scalar multiplication in G2: Σᵢ scalars[i] * bases[i]
    fn g2_msm<F: JoltField>(bases: &[Self::G2], scalars: &[F]) -> Self::G2;

    /// Generate a random G1 element
    fn random_g1<R: rand_core::RngCore>(rng: &mut R) -> Self::G1;
}

use ark_bn254::{Bn254, Fq12, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
#[cfg(feature = "zk")]
use ark_bn254::Fq;
use ark_ec::{pairing::Pairing, AdditiveGroup, AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{PrimeField, Zero};
use ark_std::UniformRand;
use dory::backends::arkworks::ArkG1;
use std::ops::MulAssign;

macro_rules! impl_group_ops {
    ($Name:ident, $Inner:ty, $field_conv:ident) => {
        impl Add for $Name {
            type Output = Self;
            fn add(self, rhs: Self) -> Self {
                $Name(self.0 + rhs.0)
            }
        }
        impl<'a> Add<&'a $Name> for $Name {
            type Output = Self;
            fn add(self, rhs: &'a $Name) -> Self {
                $Name(self.0 + rhs.0)
            }
        }
        impl Sub for $Name {
            type Output = Self;
            fn sub(self, rhs: Self) -> Self {
                $Name(self.0 - rhs.0)
            }
        }
        impl<'a> Sub<&'a $Name> for $Name {
            type Output = Self;
            fn sub(self, rhs: &'a $Name) -> Self {
                $Name(self.0 - rhs.0)
            }
        }
        impl Neg for $Name {
            type Output = Self;
            fn neg(self) -> Self {
                $Name(-self.0)
            }
        }
        impl AddAssign for $Name {
            fn add_assign(&mut self, rhs: Self) {
                self.0 += rhs.0;
            }
        }
        impl SubAssign for $Name {
            fn sub_assign(&mut self, rhs: Self) {
                self.0 -= rhs.0;
            }
        }
        impl<F: JoltField> Mul<F> for $Name {
            type Output = Self;
            fn mul(mut self, rhs: F) -> Self {
                self.0.mul_assign($field_conv(&rhs));
                self
            }
        }
    };
}

macro_rules! impl_group_element {
    ($Name:ident, $Proj:ty, $field_conv:ident) => {
        impl JoltGroupElement for $Name {
            fn zero() -> Self {
                $Name(<$Proj>::zero())
            }
            fn is_zero(&self) -> bool {
                self.0.is_zero()
            }
            fn double(&self) -> Self {
                $Name(AdditiveGroup::double(&self.0))
            }
            fn scalar_mul<F: JoltField>(&self, scalar: &F) -> Self {
                $Name(self.0 * $field_conv(scalar))
            }
        }
    };
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Bn254G1(pub G1Projective);
impl_group_ops!(Bn254G1, G1Projective, jolt_field_to_fr);
impl_group_element!(Bn254G1, G1Projective, jolt_field_to_fr);

impl From<ArkG1> for Bn254G1 {
    fn from(value: ArkG1) -> Self {
        Bn254G1(value.0)
    }
}

impl From<G1Projective> for Bn254G1 {
    fn from(value: G1Projective) -> Self {
        Bn254G1(value)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Bn254G2(pub G2Projective);
impl_group_ops!(Bn254G2, G2Projective, jolt_field_to_fr);
impl_group_element!(Bn254G2, G2Projective, jolt_field_to_fr);

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Bn254GT(pub Fq12);

impl Add for Bn254GT {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        Bn254GT(self.0 + rhs.0)
    }
}
impl<'a> Add<&'a Bn254GT> for Bn254GT {
    type Output = Self;
    fn add(self, rhs: &'a Bn254GT) -> Self {
        Bn254GT(self.0 + rhs.0)
    }
}
impl AddAssign for Bn254GT {
    fn add_assign(&mut self, rhs: Self) {
        self.0 += rhs.0;
    }
}

/// The BN254 pairing curve implementation
#[derive(Clone, Debug, Default)]
pub struct Bn254Curve;

impl JoltCurve for Bn254Curve {
    type G1 = Bn254G1;
    type G2 = Bn254G2;
    type GT = Bn254GT;

    fn g1_generator() -> Self::G1 {
        Bn254G1(G1Affine::generator().into())
    }

    fn g2_generator() -> Self::G2 {
        Bn254G2(G2Affine::generator().into())
    }

    fn pairing(g1: &Self::G1, g2: &Self::G2) -> Self::GT {
        Bn254GT(Bn254::pairing(g1.0, g2.0).0)
    }

    fn multi_pairing(g1s: &[Self::G1], g2s: &[Self::G2]) -> Self::GT {
        debug_assert_eq!(g1s.len(), g2s.len());

        let g1_affines: Vec<G1Affine> = g1s.iter().map(|g| g.0.into_affine()).collect();
        let g2_affines: Vec<G2Affine> = g2s.iter().map(|g| g.0.into_affine()).collect();

        Bn254GT(Bn254::multi_pairing(&g1_affines, &g2_affines).0)
    }

    fn g1_msm<F: JoltField>(bases: &[Self::G1], scalars: &[F]) -> Self::G1 {
        debug_assert_eq!(bases.len(), scalars.len());

        let affine_bases: Vec<G1Affine> = bases.iter().map(|b| b.0.into_affine()).collect();
        let fr_scalars: Vec<Fr> = scalars.iter().map(jolt_field_to_fr).collect();
        let bigint_scalars: Vec<_> = fr_scalars.iter().map(|s| s.into_bigint()).collect();

        Bn254G1(G1Projective::msm_bigint(&affine_bases, &bigint_scalars))
    }

    fn g2_msm<F: JoltField>(bases: &[Self::G2], scalars: &[F]) -> Self::G2 {
        debug_assert_eq!(bases.len(), scalars.len());

        let affine_bases: Vec<G2Affine> = bases.iter().map(|b| b.0.into_affine()).collect();
        let fr_scalars: Vec<Fr> = scalars.iter().map(jolt_field_to_fr).collect();
        let bigint_scalars: Vec<_> = fr_scalars.iter().map(|s| s.into_bigint()).collect();

        Bn254G2(G2Projective::msm_bigint(&affine_bases, &bigint_scalars))
    }

    fn random_g1<R: rand_core::RngCore>(rng: &mut R) -> Self::G1 {
        Bn254G1(G1Projective::rand(rng))
    }
}

// ============================================================================
// Grumpkin curve (ZK Pedersen commitments)
//
// Grumpkin's base field = BN254's scalar field (Fr), making Grumpkin G1
// operations native in BN254 Groth16 circuits (~1,775 constraints/scalar_mul
// vs ~380K for emulated BN254 G1 ops).
// ============================================================================

#[cfg(feature = "zk")]
mod grumpkin {
    use super::*;
    use ark_grumpkin::Projective as GrumpkinProjective;

    #[derive(
        Clone, Copy, Debug, Default, Eq, PartialEq, CanonicalSerialize, CanonicalDeserialize,
    )]
    pub struct GrumpkinG1(pub GrumpkinProjective);
    impl_group_ops!(GrumpkinG1, GrumpkinProjective, jolt_field_to_grumpkin_fr);
    impl_group_element!(GrumpkinG1, GrumpkinProjective, jolt_field_to_grumpkin_fr);

    /// Convert a JoltField element to Grumpkin's scalar field (= BN254 Fq).
    ///
    /// Grumpkin's scalar field and BN254's base field are the same prime field.
    /// This is the 2-cycle relationship: ark_grumpkin::Fr = ark_bn254::Fq.
    #[inline]
    fn jolt_field_to_grumpkin_fr<F: JoltField>(f: &F) -> Fq {
        let mut bytes = [0u8; 32];
        f.serialize_uncompressed(&mut bytes[..])
            .expect("serialization should succeed");
        Fq::from_le_bytes_mod_order(&bytes)
    }

    impl From<Bn254G1> for GrumpkinG1 {
        /// Deterministic mapping from BN254 G1 to Grumpkin G1.
        ///
        /// Used to derive Grumpkin Pedersen generators from the Dory URS.
        /// This is NOT a homomorphism — it's a hash-to-curve derivation.
        fn from(bn254_point: Bn254G1) -> Self {
            use rand_chacha::ChaCha20Rng;
            use rand_core::SeedableRng;
            use sha3::Digest;

            let mut buf = Vec::new();
            bn254_point
                .serialize_compressed(&mut buf)
                .expect("serialization should succeed");
            let hash = sha3::Sha3_256::digest(&buf);
            let mut rng = ChaCha20Rng::from_seed(hash.into());
            GrumpkinG1(GrumpkinProjective::rand(&mut rng))
        }
    }

    impl From<crate::poly::commitment::dory::ArkG1> for GrumpkinG1 {
        /// Convert a Dory ArkG1 (BN254 G1) to GrumpkinG1 via Bn254G1.
        ///
        /// Used by `DoryCommitmentScheme::ZkEvalCommitment<GrumpkinCurve>` to convert
        /// the eval commitment point. Note: this is a hash-to-curve derivation, not a
        /// group homomorphism. Eval commitment verification should be handled natively
        /// in the gnark circuit, not through this conversion.
        fn from(ark_point: crate::poly::commitment::dory::ArkG1) -> Self {
            GrumpkinG1::from(Bn254G1(ark_point.0))
        }
    }

    #[derive(Clone, Debug, Default)]
    pub struct GrumpkinCurve;

    impl JoltCurve for GrumpkinCurve {
        type G1 = GrumpkinG1;
        type G2 = GrumpkinG1; // stub — Grumpkin has no pairing
        type GT = Bn254GT; // stub

        fn g1_generator() -> Self::G1 {
            use ark_ec::AffineRepr;
            GrumpkinG1(ark_grumpkin::Affine::generator().into())
        }

        fn g2_generator() -> Self::G2 {
            unimplemented!("Grumpkin has no G2 for pairing")
        }

        fn pairing(_g1: &Self::G1, _g2: &Self::G2) -> Self::GT {
            unimplemented!("Grumpkin has no pairing")
        }

        fn multi_pairing(_g1s: &[Self::G1], _g2s: &[Self::G2]) -> Self::GT {
            unimplemented!("Grumpkin has no pairing")
        }

        fn g1_msm<F: JoltField>(bases: &[Self::G1], scalars: &[F]) -> Self::G1 {
            debug_assert_eq!(bases.len(), scalars.len());

            let affine_bases: Vec<ark_grumpkin::Affine> =
                bases.iter().map(|b| b.0.into_affine()).collect();
            let fq_scalars: Vec<Fq> = scalars.iter().map(jolt_field_to_grumpkin_fr).collect();
            let bigint_scalars: Vec<_> = fq_scalars.iter().map(|s| s.into_bigint()).collect();

            GrumpkinG1(GrumpkinProjective::msm_bigint(&affine_bases, &bigint_scalars))
        }

        fn g2_msm<F: JoltField>(_bases: &[Self::G2], _scalars: &[F]) -> Self::G2 {
            unimplemented!("Grumpkin has no G2 for pairing")
        }

        fn random_g1<R: rand_core::RngCore>(rng: &mut R) -> Self::G1 {
            GrumpkinG1(GrumpkinProjective::rand(rng))
        }
    }
}

#[cfg(feature = "zk")]
pub use grumpkin::{GrumpkinCurve, GrumpkinG1};

/// Convert a JoltField element to BN254 Fr.
///
/// This assumes the JoltField is compatible with BN254's scalar field.
/// For ark_bn254::Fr, this is a direct conversion.
#[inline]
fn jolt_field_to_fr<F: JoltField>(f: &F) -> Fr {
    // Serialize the field element and deserialize as Fr
    // This is safe because JoltField elements are assumed to be in the same field
    let mut bytes = [0u8; 32];
    f.serialize_uncompressed(&mut bytes[..])
        .expect("serialization should succeed");
    Fr::from_le_bytes_mod_order(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::UniformRand;
    use rand::thread_rng;

    #[test]
    fn test_g1_operations() {
        let g = Bn254Curve::g1_generator();
        let zero = Bn254G1::zero();

        assert!(zero.is_zero());
        assert!(!g.is_zero());
        assert_eq!(g + zero, g);
        assert_eq!(g - g, zero);
    }

    #[test]
    fn test_g2_operations() {
        let g = Bn254Curve::g2_generator();
        let zero = Bn254G2::zero();

        assert!(zero.is_zero());
        assert!(!g.is_zero());
        assert_eq!(g + zero, g);
        assert_eq!(g - g, zero);
    }

    #[test]
    fn test_pairing_bilinearity() {
        let mut rng = thread_rng();
        let a = Fr::rand(&mut rng);
        let b = Fr::rand(&mut rng);

        let g1 = Bn254Curve::g1_generator();
        let g2 = Bn254Curve::g2_generator();

        let g1_a = g1.scalar_mul(&a);
        let g2_b = g2.scalar_mul(&b);

        // e(a*G1, b*G2) should relate to e(G1, G2)^(a*b)
        let pairing1 = Bn254Curve::pairing(&g1_a, &g2_b);
        let pairing2 = Bn254Curve::pairing(&g1.scalar_mul(&(a * b)), &g2);

        assert_eq!(pairing1, pairing2);
    }

    #[test]
    fn test_g1_msm() {
        let g = Bn254Curve::g1_generator();
        let scalars = vec![Fr::from(2u64), Fr::from(3u64)];
        let bases = vec![g, g];

        let result = Bn254Curve::g1_msm(&bases, &scalars);
        let expected = g.scalar_mul(&Fr::from(5u64));

        assert_eq!(result, expected);
    }
}
