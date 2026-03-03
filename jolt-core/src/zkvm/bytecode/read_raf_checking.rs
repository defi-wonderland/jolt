use std::{any::Any, array, cell::RefCell, iter::once, sync::Arc};

use num_traits::Zero;

use crate::{
    field::JoltField,
    poly::{
        eq_poly::EqPolynomial,
        identity_poly::IdentityPolynomial,
        multilinear_polynomial::{
            BindingOrder, MultilinearPolynomial, PolynomialBinding, PolynomialEvaluation,
        },
        opening_proof::{
            OpeningAccumulator, OpeningPoint, ProverOpeningAccumulator, SumcheckId,
            BIG_ENDIAN,
        },
        ra_poly::RaPolynomial,
        split_eq_poly::GruenSplitEqPolynomial,
        unipoly::UniPoly,
    },
    subprotocols::{
        mles_product_sum::eval_linear_prod_assign,
        sumcheck_prover::SumcheckInstanceProver,
        sumcheck_verifier::{SumcheckInstanceParams, SumcheckInstanceVerifier},
    },
    transcripts::Transcript,
    utils::{math::Math, thread::unsafe_allocate_zero_vec},
    zkvm::{
        bytecode::BytecodePreprocessing,
        config::OneHotParams,
        instruction::{
            CircuitFlags, Flags, InstructionFlags, InstructionLookup, InterleavedBitsMarker,
            NUM_CIRCUIT_FLAGS, NUM_INSTRUCTION_FLAGS,
        },
        lookup_table::{LookupTables, NUM_LOOKUP_TABLES},
        witness::{CommittedPolynomial, VirtualPolynomial},
    },
};
use allocative::Allocative;
#[cfg(feature = "allocative")]
use allocative::FlameGraphBuilder;
use common::constants::{REGISTER_COUNT, XLEN};
use itertools::{zip_eq, Itertools};
use rayon::prelude::*;
use strum::{EnumCount, IntoEnumIterator};
use tracer::instruction::{Cycle, Instruction};

// =============================================================================
// Symbolic bytecode support (universal circuit transpilation)
// =============================================================================

thread_local! {
    static PENDING_BYTECODE_INSTRUCTIONS: RefCell<Option<Box<dyn Any>>> = RefCell::new(None);
    /// Captured eq_r_register tables and gammas from compute_val_polys execution.
    /// Used by the transpiler to fix up witness values after symbolic verification.
    static CAPTURED_BYTECODE_CHALLENGES: RefCell<Option<Box<dyn Any>>> = RefCell::new(None);
}

/// Pre-allocated symbolic variables for a single bytecode instruction.
///
/// For universal circuit transpilation, concrete instruction data (address, imm, flags,
/// register eq lookups, lookup table contribution) are replaced with witness variables.
/// Branches like `if flag { lc += gamma }` become `flag_var * gamma`.
///
/// Fields that depend on challenge-derived values (`eq_r_register_4`, `eq_r_register_5_rd`,
/// `stage5_lookup_contribution`) are allocated with placeholder witness values that must be
/// fixed up after symbolic verification completes.
#[derive(Clone)]
pub struct SymbolicInstruction<F> {
    pub address: F,
    pub imm: F,
    pub circuit_flags: [F; NUM_CIRCUIT_FLAGS],
    pub instruction_flags: [F; NUM_INSTRUCTION_FLAGS],
    /// eq(rd, r_register_4) * gamma4[0] + eq(rs1, r_register_4) * gamma4[1] + eq(rs2, r_register_4) * gamma4[2]
    /// Provided as 3 separate witness values for stage 4.
    pub eq_r_register_4: [F; 3], // [rd_eq4, rs1_eq4, rs2_eq4]
    /// eq(rd, r_register_5) for stage 5.
    pub eq_r_register_5_rd: F,
    /// 1 - is_interleaved_operands for stage 5.
    pub stage5_not_interleaved: F,
    /// gamma[2 + table_idx] for the instruction's lookup table, or 0 if no table.
    pub stage5_lookup_contribution: F,
}

/// Pending symbolic instructions for compute_val_polys.
#[derive(Clone)]
pub struct PendingBytecodeInstructions<F> {
    pub instructions: Vec<SymbolicInstruction<F>>,
    /// Concrete register numbers for each instruction (for witness fixup).
    /// Each entry: (rd: Option<u8>, rs1: Option<u8>, rs2: Option<u8>)
    pub register_indices: Vec<(Option<u8>, Option<u8>, Option<u8>)>,
    /// Concrete lookup table index for each instruction (for witness fixup).
    /// None if the instruction has no lookup table.
    pub lookup_table_indices: Vec<Option<usize>>,
}

/// Captured concrete eq_r_register tables and gammas from compute_val_polys.
/// Used to fix up placeholder witness values after symbolic verification.
#[derive(Clone)]
pub struct CapturedBytecodeData<F> {
    pub eq_r_register_4: Vec<F>,
    pub eq_r_register_5: Vec<F>,
    pub stage5_gammas: Vec<F>,
}

pub fn set_pending_bytecode_instructions<F: Clone + 'static>(
    vals: PendingBytecodeInstructions<F>,
) {
    PENDING_BYTECODE_INSTRUCTIONS.with(|cell| {
        *cell.borrow_mut() = Some(Box::new(vals));
    });
}

fn get_pending_bytecode_instructions<F: Clone + 'static>(
) -> Option<PendingBytecodeInstructions<F>> {
    PENDING_BYTECODE_INSTRUCTIONS.with(|cell| {
        cell.borrow()
            .as_ref()
            .map(|b| b.downcast_ref::<PendingBytecodeInstructions<F>>().unwrap().clone())
    })
}

pub fn set_captured_bytecode_data<F: Clone + 'static>(data: CapturedBytecodeData<F>) {
    CAPTURED_BYTECODE_CHALLENGES.with(|cell| {
        *cell.borrow_mut() = Some(Box::new(data));
    });
}

pub fn take_captured_bytecode_data<F: Clone + 'static>() -> Option<CapturedBytecodeData<F>> {
    CAPTURED_BYTECODE_CHALLENGES.with(|cell| {
        cell.borrow_mut()
            .take()
            .map(|b| *b.downcast::<CapturedBytecodeData<F>>().unwrap())
    })
}

/// Number of batched read-checking sumchecks bespokely
const N_STAGES: usize = 5;

/// Bytecode instruction: multi-stage Read + RAF sumcheck (N_STAGES = 5).
///
/// Stages virtualize different claim families (Stage1: Spartan outer; Stage2: product-virtualized
/// flags; Stage3: Shift; Stage4: Registers RW; Stage5: Registers val-eval + Instruction lookups).
///
/// The input claim is a γ-weighted RLC of stage rv_claims plus RAF contributions folded into
/// stages 1 and 3 via the identity polynomial. Address vars are bound in `d` chunks; cycle vars
/// are bound with per-stage `GruenSplitEqPolynomial` (low-to-high binding), producing univariates
/// of degree `d + 1` (cubic only when `d = 2`).
///
/// Challenge notation:
/// - γ: the stage-folding scalar with powers `params.gamma_powers = transcript.challenge_scalar_powers(7)`.
/// - β_s: per-stage scalars used *within* Val_s encodings (`stage{s}_gammas = transcript.challenge_scalar_powers(...)`),
///   sampled separately for each stage.
///
/// Mathematical claim:
/// - Let K = 2^{log_K} and T = 2^{log_T}.
/// - For stage s ∈ {1,2,3,4,5}, let r_s ∈ F^{log_T} and define eq_s(j) = EqPolynomial(j; r_s).
/// - Let r_addr ∈ F^{log_K}. Let ra(k, j) ∈ {0,1} be the indicator that cycle j maps to bytecode
///   row index k (i.e. `k = get_pc(cycle_j)`; this is *not* the ELF/instruction address).
///   Implemented as ∏_{i=0}^{d-1} ra_i(k_i, j) via one-hot chunking of the bytecode index k.
/// - Int(k) = 1 for all k (evaluation of the IdentityPolynomial over address variables).
/// - Define per-stage Val_s(k) (address-only) as implemented by `compute_val_*`:
///   * Stage1: Val_1(k) = unexpanded_pc(k) + β_1·imm(k) + Σ_t β_1^{2+t}·circuit_flag_t(k).
///   * Stage2: Val_2(k) = 1_{jump}(k) + β_2·1_{branch}(k) + β_2^2·rd_addr(k) + β_2^3·1_{write_lookup_to_rd}(k)
///   + β_2^4·1_{VirtualInstruction}(k).
///   * Stage3: Val_3(k) = imm(k) + β_3·unexpanded_pc(k) + β_3^2·1_{L_is_rs1}(k) + β_3^3·1_{L_is_pc}(k)
///   + β_3^4·1_{R_is_rs2}(k) + β_3^5·1_{R_is_imm}(k) + β_3^6·1_{IsNoop}(k)
///   + β_3^7·1_{VirtualInstruction}(k) + β_3^8·1_{IsFirstInSequence}(k).
///   * Stage4: Val_4(k) = 1_{rd=r}(k) + β_4·1_{rs1=r}(k) + β_4^2·1_{rs2=r}(k), where r is fixed by opening.
///   * Stage5: Val_5(k) = 1_{rd=r}(k) + β_5·1_{¬interleaved}(k) + Σ_i β_5^{2+i}·1_{table=i}(k).
///
///   Here, unexpanded_pc(k) is the instruction's ELF/address field (`instr.address`) stored in the bytecode row k.
///
/// Accumulator-provided LHS (RLC of stage claims with RAF):
///   rv_1(r_1) + γ·rv_2(r_2) + γ^2·rv_3(r_3) + γ^3·rv_4(r_4) + γ^4·rv_5(r_5)
///   + γ^5·raf_1(r_1) + γ^6·raf_3(r_3).
///
/// Sumcheck RHS proved (double sum over cycles and addresses):
///   Σ_{j=0}^{T-1} Σ_{k=0}^{K-1} ra(k, j) · [
///       γ^0·eq_1(j)·Val_1(k) + γ^1·eq_2(j)·Val_2(k) + γ^2·eq_3(j)·Val_3(k)
///     + γ^3·eq_4(j)·Val_4(k) + γ^4·eq_5(j)·Val_5(k)
///     + γ^5·eq_1(j)·Int(k)   + γ^6·eq_3(j)·Int(k)
///   ].
///
/// Thus the identity established by this sumcheck is:
///   rv_1(r_1) + γ·rv_2(r_2) + γ^2·rv_3(r_3) + γ^3·rv_4(r_4) + γ^4·rv_5(r_5)
///   + γ^5·raf_1(r_1) + γ^6·raf_3(r_3)
///     = Σ_{j,k} ra(k, j) · [ Σ_{s=1}^{5} γ^{s-1}·eq_s(j)·Val_s(k) + γ^5·eq_1(j)·Int(k) + γ^6·eq_3(j)·Int(k) ].
///
/// Binding/implementation notes:
/// - Address variables are bound first (low→high in the sumcheck binding order) in `d` chunks,
///   accumulating `F_i` and `v` tables;
///   this materializes the address-only Val_s(k) evaluations and sets up `ra_i` polynomials.
/// - Cycle variables are then bound (low→high) per stage with `GruenSplitEqPolynomial`, using
///   previous-round claims to recover the degree-(d+1) univariate each round.
/// - RAF injection uses `VirtualPolynomial::PC` (not `UnexpandedPC`): `raf_claim` comes from
///   `SumcheckId::SpartanOuter` and `raf_shift_claim` from `SumcheckId::SpartanShift`.
/// - The Stage3 RAF weight is “offset inside the stage”: the prover uses `γ^4 * raf_shift_claim`
///   in the Stage3 per-stage claim, then the stage itself is folded with an outer factor `γ^2`,
///   yielding the advertised `γ^6` overall.
#[derive(Allocative)]
pub struct BytecodeReadRafSumcheckProver<F: JoltField> {
    /// Per-stage address MLEs F_i(k) built from eq(r_cycle_stage_i, (chunk_index, j)),
    /// bound low-to-high during the address-binding phase.
    F: [MultilinearPolynomial<F>; N_STAGES],
    /// Chunked RA polynomials over address variables (one per dimension `d`), used to form
    /// the product ∏_i ra_i during the cycle-binding phase.
    ra: Vec<RaPolynomial<u8, F>>,
    /// Binding challenges for the first log_K variables of the sumcheck
    r_address_prime: Vec<F::Challenge>,
    /// Per-stage Gruen-split eq polynomials over cycle vars (low-to-high binding order).
    gruen_eq_polys: [GruenSplitEqPolynomial<F>; N_STAGES],
    /// Previous-round claims s_i(0)+s_i(1) per stage, needed for degree-(d+1) univariate recovery.
    prev_round_claims: [F; N_STAGES],
    /// Round polynomials per stage for advancing to the next claim at r_j.
    prev_round_polys: Option<[UniPoly<F>; N_STAGES]>,
    /// Final sumcheck claims of stage Val polynomials (with RAF Int folded where applicable).
    bound_val_evals: Option<[F; N_STAGES]>,
    /// Trace for computing PCs on the fly in init_log_t_rounds.
    #[allocative(skip)]
    trace: Arc<Vec<Cycle>>,
    /// Bytecode preprocessing for computing PCs.
    #[allocative(skip)]
    bytecode_preprocessing: Arc<BytecodePreprocessing>,
    pub params: BytecodeReadRafSumcheckParams<F>,
}

impl<F: JoltField> BytecodeReadRafSumcheckProver<F> {
    #[tracing::instrument(skip_all, name = "BytecodeReadRafSumcheckProver::initialize")]
    pub fn initialize(
        params: BytecodeReadRafSumcheckParams<F>,
        trace: Arc<Vec<Cycle>>,
        bytecode_preprocessing: Arc<BytecodePreprocessing>,
    ) -> Self {
        let claim_per_stage = [
            params.rv_claims[0] + params.gamma_powers[5] * params.raf_claim,
            params.rv_claims[1],
            params.rv_claims[2] + params.gamma_powers[4] * params.raf_shift_claim,
            params.rv_claims[3],
            params.rv_claims[4],
        ];

        // Two-table split-eq optimization for computing F[stage][k] = Σ_{c: PC(c)=k} eq(r_cycle, c).
        //
        // Double summation pattern:
        //   F[stage][k] = Σ_{c_hi} E_hi[c_hi] × ( Σ_{c_lo : PC(c)=k} E_lo[c_lo] )
        //
        // Inner sum (over c_lo): ADDITIONS ONLY - accumulate E_lo contributions by PC
        // Outer sum (over c_hi): ONE multiplication per touched PC, not per cycle
        //
        // This reduces multiplications from O(T × N_STAGES) to O(touched_PCs × out_len × N_STAGES)
        let T = trace.len();
        let K = params.K;
        let log_T = params.log_T;

        // Optimal split: sqrt(T) for balanced tables
        let lo_bits = log_T / 2;
        let hi_bits = log_T - lo_bits;
        let in_len: usize = 1 << lo_bits; // E_lo size (inner loop)
        let out_len: usize = 1 << hi_bits; // E_hi size (outer loop)

        // Pre-compute E_hi[stage][c_hi] and E_lo[stage][c_lo] for all stages in parallel
        let (E_hi, E_lo): ([Vec<F>; N_STAGES], [Vec<F>; N_STAGES]) = rayon::join(
            || {
                params
                    .r_cycles
                    .each_ref()
                    .map(|r_cycle| EqPolynomial::evals(&r_cycle[..hi_bits]))
            },
            || {
                params
                    .r_cycles
                    .each_ref()
                    .map(|r_cycle| EqPolynomial::evals(&r_cycle[hi_bits..]))
            },
        );

        // Process by c_hi blocks, distributing work evenly among threads
        let num_threads = rayon::current_num_threads();
        let chunk_size = out_len.div_ceil(num_threads);

        // Double summation: outer sum over c_hi, inner sum over c_lo
        let F: [Vec<F>; N_STAGES] = E_hi[0]
            .par_chunks(chunk_size)
            .enumerate()
            .map(|(chunk_idx, chunk)| {
                // Per-thread accumulators for final F
                let mut partial: [Vec<F>; N_STAGES] =
                    array::from_fn(|_| unsafe_allocate_zero_vec(K));

                // Per-c_hi inner accumulators (reused across c_hi iterations)
                let mut inner: [Vec<F>; N_STAGES] = array::from_fn(|_| unsafe_allocate_zero_vec(K));

                // Track which PCs were touched in this c_hi block
                let mut touched = Vec::with_capacity(in_len);

                let chunk_start = chunk_idx * chunk_size;
                for (local_idx, _) in chunk.iter().enumerate() {
                    let c_hi = chunk_start + local_idx;
                    let c_hi_base = c_hi * in_len;

                    // Clear inner accumulators for touched PCs only
                    for &k in &touched {
                        for stage in 0..N_STAGES {
                            inner[stage][k] = F::zero();
                        }
                    }
                    touched.clear();

                    // INNER SUM: accumulate E_lo by PC (ADDITIONS ONLY, no multiplications)
                    for c_lo in 0..in_len {
                        let c = c_hi_base + c_lo;
                        if c >= T {
                            break;
                        }

                        let pc = bytecode_preprocessing.get_pc(&trace[c]);

                        // Track touched PCs (avoid duplicates with a simple check)
                        if inner[0][pc].is_zero() {
                            touched.push(pc);
                        }

                        // Accumulate E_lo contributions (addition only!)
                        for stage in 0..N_STAGES {
                            inner[stage][pc] += E_lo[stage][c_lo];
                        }
                    }

                    // OUTER SUM: multiply by E_hi and add to partial (sparse)
                    for &k in &touched {
                        for stage in 0..N_STAGES {
                            partial[stage][k] += E_hi[stage][c_hi] * inner[stage][k];
                        }
                    }
                }

                partial
            })
            .reduce(
                || array::from_fn(|_| unsafe_allocate_zero_vec(K)),
                |mut a, b| {
                    for stage in 0..N_STAGES {
                        a[stage]
                            .par_iter_mut()
                            .zip(b[stage].par_iter())
                            .for_each(|(a, b)| *a += *b);
                    }
                    a
                },
            );

        #[cfg(test)]
        {
            // Verify that for each stage i: sum(val_i[k] * F_i[k] * eq_i[k]) = rv_claim_i
            for i in 0..N_STAGES {
                let computed_claim: F = (0..params.K)
                    .into_par_iter()
                    .map(|k| {
                        let val_k = params.val_polys[i].get_bound_coeff(k);
                        let F_k = F[i][k];
                        val_k * F_k
                    })
                    .sum();
                assert_eq!(
                    computed_claim,
                    params.rv_claims[i],
                    "Stage {} mismatch: computed {} != expected {}",
                    i + 1,
                    computed_claim,
                    params.rv_claims[i]
                );
            }
        }

        let F = F.map(MultilinearPolynomial::from);

        let gruen_eq_polys = params
            .r_cycles
            .each_ref()
            .map(|r_cycle| GruenSplitEqPolynomial::new(r_cycle, BindingOrder::LowToHigh));

        Self {
            F,
            ra: Vec::with_capacity(params.d),
            r_address_prime: Vec::with_capacity(params.log_K),
            gruen_eq_polys,
            prev_round_claims: claim_per_stage,
            prev_round_polys: None,
            bound_val_evals: None,
            trace,
            bytecode_preprocessing,
            params,
        }
    }

    fn init_log_t_rounds(&mut self) {
        let int_poly = self.params.int_poly.final_sumcheck_claim();

        // We have a separate Val polynomial for each stage
        // Additionally, for stages 1 and 3 we have an Int polynomial for RAF
        // So we would have:
        // Stage 1: gamma^0 * (Val_1 + gamma^5 * Int)
        // Stage 2: gamma^1 * (Val_2)
        // Stage 3: gamma^2 * (Val_3 + gamma^4 * Int)
        // Stage 4: gamma^3 * (Val_4)
        // Stage 5: gamma^4 * (Val_5)
        // Which matches with the input claim:
        // rv_1 + gamma * rv_2 + gamma^2 * rv_3 + gamma^3 * rv_4 + gamma^4 * rv_5 + gamma^5 * raf_1 + gamma^6 * raf_3
        self.bound_val_evals = Some(
            self.params
                .val_polys
                .iter()
                .zip([
                    int_poly * self.params.gamma_powers[5],
                    F::zero(),
                    int_poly * self.params.gamma_powers[4],
                    F::zero(),
                    F::zero(),
                ])
                .map(|(poly, int_poly)| poly.final_sumcheck_claim() + int_poly)
                .collect::<Vec<F>>()
                .try_into()
                .unwrap(),
        );

        // Reverse r_address_prime to get the correct order (it was built low-to-high)
        let mut r_address = std::mem::take(&mut self.r_address_prime);
        r_address.reverse();

        // Drop log_K phase data that's no longer needed (val_polys reduced to bound_val_evals)
        // F polynomials are fully bound and can be dropped
        self.F = array::from_fn(|_| MultilinearPolynomial::default());
        // val_polys are reduced to scalars in bound_val_evals
        self.params.val_polys = array::from_fn(|_| MultilinearPolynomial::default());
        // int_poly is reduced to a scalar
        self.params.int_poly = IdentityPolynomial::new(0);

        let r_address_chunks = self
            .params
            .one_hot_params
            .compute_r_address_chunks::<F>(&r_address);

        // Build RA polynomials by iterating over trace and computing PCs on the fly
        self.ra = r_address_chunks
            .iter()
            .enumerate()
            .map(|(i, r_address_chunk)| {
                let ra_i: Vec<Option<u8>> = self
                    .trace
                    .par_iter()
                    .map(|cycle| {
                        let pc = self.bytecode_preprocessing.get_pc(cycle);
                        Some(self.params.one_hot_params.bytecode_pc_chunk(pc, i))
                    })
                    .collect();
                RaPolynomial::new(Arc::new(ra_i), EqPolynomial::evals(r_address_chunk))
            })
            .collect();

        // Drop trace and preprocessing - no longer needed after this
        self.trace = Arc::new(Vec::new());
    }
}

impl<F: JoltField, T: Transcript> SumcheckInstanceProver<F, T>
    for BytecodeReadRafSumcheckProver<F>
{
    fn get_params(&self) -> &dyn SumcheckInstanceParams<F> {
        &self.params
    }

    #[tracing::instrument(skip_all, name = "BytecodeReadRafSumcheckProver::compute_message")]
    fn compute_message(&mut self, round: usize, _previous_claim: F) -> UniPoly<F> {
        if round < self.params.log_K {
            const DEGREE: usize = 2;

            // Evaluation at [0, 2] for each stage.
            let eval_per_stage: [[F; DEGREE]; N_STAGES] = (0..self.params.val_polys[0].len() / 2)
                .into_par_iter()
                .map(|i| {
                    let ra_evals = self.F.each_ref().map(|poly| {
                        poly.sumcheck_evals_array::<DEGREE>(i, BindingOrder::LowToHigh)
                    });

                    let int_evals =
                        self.params.int_poly
                            .sumcheck_evals(i, DEGREE, BindingOrder::LowToHigh);

                    // We have a separate Val polynomial for each stage
                    // Additionally, for stages 1 and 3 we have an Int polynomial for RAF
                    // So we would have:
                    // Stage 1: Val_1 + gamma^5 * Int
                    // Stage 2: Val_2
                    // Stage 3: Val_3 + gamma^4 * Int
                    // Stage 4: Val_4
                    // Stage 5: Val_5
                    // Which matches with the input claim:
                    // rv_1 + gamma * rv_2 + gamma^2 * rv_3 + gamma^3 * rv_4 + gamma^4 * rv_5 + gamma^5 * raf_1 + gamma^6 * raf_3
                    let mut val_evals = self
                        .params.val_polys
                        .iter()
                        // Val polynomials
                        .map(|val| val.sumcheck_evals_array::<DEGREE>(i, BindingOrder::LowToHigh))
                        // Here are the RAF polynomials and their powers
                        .zip([Some(&int_evals), None, Some(&int_evals), None, None])
                        .zip([Some(self.params.gamma_powers[5]), None, Some(self.params.gamma_powers[4]), None, None])
                        .map(|((val_evals, int_evals), gamma)| {
                            std::array::from_fn::<F, DEGREE, _>(|j| {
                                val_evals[j]
                                    + int_evals.map_or(F::zero(), |int_evals| {
                                        int_evals[j] * gamma.unwrap()
                                    })
                            })
                        });

                    array::from_fn(|stage| {
                        let [ra_at_0, ra_at_2] = ra_evals[stage];
                        let [val_at_0, val_at_2] = val_evals.next().unwrap();
                        [ra_at_0 * val_at_0, ra_at_2 * val_at_2]
                    })
                })
                .reduce(
                    || [[F::zero(); DEGREE]; N_STAGES],
                    |a, b| array::from_fn(|i| array::from_fn(|j| a[i][j] + b[i][j])),
                );

            let mut round_polys: [_; N_STAGES] = array::from_fn(|_| UniPoly::zero());
            let mut agg_round_poly = UniPoly::zero();

            for (stage, evals) in eval_per_stage.into_iter().enumerate() {
                let [eval_at_0, eval_at_2] = evals;
                let eval_at_1 = self.prev_round_claims[stage] - eval_at_0;
                let round_poly = UniPoly::from_evals(&[eval_at_0, eval_at_1, eval_at_2]);
                agg_round_poly += &(&round_poly * self.params.gamma_powers[stage]);
                round_polys[stage] = round_poly;
            }

            self.prev_round_polys = Some(round_polys);

            agg_round_poly
        } else {
            let degree = <Self as SumcheckInstanceProver<F, T>>::degree(self);

            let out_len = self.gruen_eq_polys[0].E_out_current().len();
            let in_len = self.gruen_eq_polys[0].E_in_current().len();
            let in_n_vars = in_len.log_2();

            // Evaluations on [1, ..., degree - 2, inf] (for each stage).
            let mut evals_per_stage: [Vec<F>; N_STAGES] = (0..out_len)
                .into_par_iter()
                .map(|j_hi| {
                    let mut ra_eval_pairs = vec![(F::zero(), F::zero()); self.ra.len()];
                    let mut ra_prod_evals = vec![F::zero(); degree - 1];
                    let mut evals_per_stage: [_; N_STAGES] =
                        array::from_fn(|_| vec![F::Unreduced::zero(); degree - 1]);

                    for j_lo in 0..in_len {
                        let j = j_lo + (j_hi << in_n_vars);

                        for (i, ra_i) in self.ra.iter().enumerate() {
                            let ra_i_eval_at_j_0 = ra_i.get_bound_coeff(j * 2);
                            let ra_i_eval_at_j_1 = ra_i.get_bound_coeff(j * 2 + 1);
                            ra_eval_pairs[i] = (ra_i_eval_at_j_0, ra_i_eval_at_j_1);
                        }
                        // Eval prod_i ra_i(x).
                        eval_linear_prod_assign(&ra_eval_pairs, &mut ra_prod_evals);

                        for stage in 0..N_STAGES {
                            let eq_in_eval = self.gruen_eq_polys[stage].E_in_current()[j_lo];
                            for i in 0..degree - 1 {
                                evals_per_stage[stage][i] +=
                                    eq_in_eval.mul_unreduced::<9>(ra_prod_evals[i]);
                            }
                        }
                    }

                    array::from_fn(|stage| {
                        let eq_out_eval = self.gruen_eq_polys[stage].E_out_current()[j_hi];
                        evals_per_stage[stage]
                            .iter()
                            .map(|v| eq_out_eval * F::from_montgomery_reduce(*v))
                            .collect()
                    })
                })
                .reduce(
                    || array::from_fn(|_| vec![F::zero(); degree - 1]),
                    |a, b| array::from_fn(|i| zip_eq(&a[i], &b[i]).map(|(a, b)| *a + *b).collect()),
                );
            // Multiply by bound values.
            let bound_val_evals = self.bound_val_evals.as_ref().unwrap();
            for (stage, evals) in evals_per_stage.iter_mut().enumerate() {
                evals.iter_mut().for_each(|v| *v *= bound_val_evals[stage]);
            }

            let mut round_polys: [_; N_STAGES] = array::from_fn(|_| UniPoly::zero());
            let mut agg_round_poly = UniPoly::zero();

            // Obtain round poly for each stage and perform RLC.
            for (stage, evals) in evals_per_stage.iter().enumerate() {
                let claim = self.prev_round_claims[stage];
                let round_poly = self.gruen_eq_polys[stage].gruen_poly_from_evals(evals, claim);
                agg_round_poly += &(&round_poly * self.params.gamma_powers[stage]);
                round_polys[stage] = round_poly;
            }

            self.prev_round_polys = Some(round_polys);

            agg_round_poly
        }
    }

    #[tracing::instrument(skip_all, name = "BytecodeReadRafSumcheckProver::ingest_challenge")]
    fn ingest_challenge(&mut self, r_j: F::Challenge, round: usize) {
        if let Some(prev_round_polys) = self.prev_round_polys.take() {
            self.prev_round_claims = prev_round_polys.map(|poly| poly.evaluate(&r_j));
        }

        if round < self.params.log_K {
            self.params
                .val_polys
                .iter_mut()
                .for_each(|poly| poly.bind_parallel(r_j, BindingOrder::LowToHigh));
            self.params
                .int_poly
                .bind_parallel(r_j, BindingOrder::LowToHigh);
            self.F
                .iter_mut()
                .for_each(|poly| poly.bind_parallel(r_j, BindingOrder::LowToHigh));
            self.r_address_prime.push(r_j);
            if round == self.params.log_K - 1 {
                self.init_log_t_rounds();
            }
        } else {
            self.ra
                .iter_mut()
                .for_each(|ra| ra.bind_parallel(r_j, BindingOrder::LowToHigh));
            self.gruen_eq_polys
                .iter_mut()
                .for_each(|poly| poly.bind(r_j));
        }
    }

    fn cache_openings(
        &self,
        accumulator: &mut ProverOpeningAccumulator<F>,
        transcript: &mut T,
        sumcheck_challenges: &[F::Challenge],
    ) {
        let opening_point = self.params.normalize_opening_point(sumcheck_challenges);
        let (r_address, r_cycle) = opening_point.split_at(self.params.log_K);

        // Compute r_address_chunks with proper padding
        let r_address_chunks = self
            .params
            .one_hot_params
            .compute_r_address_chunks::<F>(&r_address.r);

        for i in 0..self.params.d {
            accumulator.append_sparse(
                transcript,
                vec![CommittedPolynomial::BytecodeRa(i)],
                SumcheckId::BytecodeReadRaf,
                r_address_chunks[i].clone(),
                r_cycle.clone().into(),
                vec![self.ra[i].final_sumcheck_claim()],
            );
        }
    }

    #[cfg(feature = "allocative")]
    fn update_flamegraph(&self, flamegraph: &mut FlameGraphBuilder) {
        flamegraph.visit_root(self);
    }
}

pub struct BytecodeReadRafSumcheckVerifier<F: JoltField> {
    params: BytecodeReadRafSumcheckParams<F>,
}

impl<F: JoltField> BytecodeReadRafSumcheckVerifier<F> {
    pub fn gen<A: OpeningAccumulator<F>>(
        bytecode_preprocessing: &BytecodePreprocessing,
        n_cycle_vars: usize,
        one_hot_params: &OneHotParams,
        opening_accumulator: &A,
        transcript: &mut impl Transcript,
    ) -> Self {
        Self {
            params: BytecodeReadRafSumcheckParams::gen(
                bytecode_preprocessing,
                n_cycle_vars,
                one_hot_params,
                opening_accumulator,
                transcript,
            ),
        }
    }
}

impl<F: JoltField, T: Transcript, A: OpeningAccumulator<F>> SumcheckInstanceVerifier<F, T, A>
    for BytecodeReadRafSumcheckVerifier<F>
{
    fn get_params(&self) -> &dyn SumcheckInstanceParams<F> {
        &self.params
    }

    fn expected_output_claim(
        &self,
        accumulator: &A,
        sumcheck_challenges: &[F::Challenge],
    ) -> F {
        let opening_point = self.params.normalize_opening_point(sumcheck_challenges);
        let (r_address_prime, r_cycle_prime) = opening_point.split_at(self.params.log_K);
        // r_cycle is bound LowToHigh, so reverse

        let int_poly = self.params.int_poly.evaluate(&r_address_prime.r);

        let ra_claims = (0..self.params.d).map(|i| {
            accumulator
                .get_committed_polynomial_opening(
                    CommittedPolynomial::BytecodeRa(i),
                    SumcheckId::BytecodeReadRaf,
                )
                .1
        });

        // We have a separate Val polynomial for each stage
        // Additionally, for stages 1 and 3 we have an Int polynomial for RAF
        // So we would have:
        // Stage 1: gamma^0 * (Val_1 + gamma^5 * Int)
        // Stage 2: gamma^1 * (Val_2)
        // Stage 3: gamma^2 * (Val_3 + gamma^4 * Int)
        // Stage 4: gamma^3 * (Val_4)
        // Stage 5: gamma^4 * (Val_5)
        // Which matches with the input claim:
        // rv_1 + gamma * rv_2 + gamma^2 * rv_3 + gamma^3 * rv_4 + gamma^4 * rv_5 + gamma^5 * raf_1 + gamma^6 * raf_3
        let val = self
            .params
            .val_polys
            .iter()
            .zip(&self.params.r_cycles)
            .zip(&self.params.gamma_powers)
            .zip([
                int_poly * self.params.gamma_powers[5], // RAF for Stage1
                F::zero(),                              // There's no raf for Stage2
                int_poly * self.params.gamma_powers[4], // RAF for Stage3
                F::zero(),                              // There's no raf for Stage4
                F::zero(),                              // There's no raf for Stage5
            ])
            .map(|(((val, r_cycle), gamma), int_poly)| {
                (val.evaluate(&r_address_prime.r) + int_poly)
                    * EqPolynomial::<F>::mle(r_cycle, &r_cycle_prime.r)
                    * gamma
            })
            .sum::<F>();

        ra_claims.fold(val, |running, ra_claim| running * ra_claim)
    }

    fn cache_openings(
        &self,
        accumulator: &mut A,
        transcript: &mut T,
        sumcheck_challenges: &[<F as JoltField>::Challenge],
    ) {
        let opening_point = self.params.normalize_opening_point(sumcheck_challenges);
        let (r_address, r_cycle) = opening_point.split_at(self.params.log_K);

        // Compute r_address_chunks with proper padding
        let r_address_chunks = self
            .params
            .one_hot_params
            .compute_r_address_chunks::<F>(&r_address.r);

        (0..self.params.d).for_each(|i| {
            let opening_point = [&r_address_chunks[i][..], &r_cycle.r].concat();
            accumulator.append_sparse(
                transcript,
                vec![CommittedPolynomial::BytecodeRa(i)],
                SumcheckId::BytecodeReadRaf,
                opening_point,
            );
        });
    }
}

#[derive(Allocative, Clone)]
pub struct BytecodeReadRafSumcheckParams<F: JoltField> {
    /// Index `i` stores `gamma^i`.
    pub gamma_powers: Vec<F>,
    /// RLC of stage rv_claims and RAF claims (per Stage1/Stage3) used as the sumcheck LHS.
    pub input_claim: F,
    /// RaParams
    pub one_hot_params: OneHotParams,
    /// Bytecode length.
    pub K: usize,
    /// log2(K) and log2(T) used to determine round counts.
    pub log_K: usize,
    pub log_T: usize,
    /// Number of address chunks (and RA polynomials in the product).
    pub d: usize,
    /// Stage Val polynomials evaluated over address vars.
    pub val_polys: [MultilinearPolynomial<F>; N_STAGES],
    /// Stage rv claims.
    pub rv_claims: [F; N_STAGES],
    pub raf_claim: F,
    pub raf_shift_claim: F,
    /// Identity polynomial over address vars used to inject RAF contributions.
    pub int_poly: IdentityPolynomial<F>,
    pub r_cycles: [Vec<F::Challenge>; N_STAGES],
}

impl<F: JoltField> BytecodeReadRafSumcheckParams<F> {
    #[tracing::instrument(skip_all, name = "BytecodeReadRafSumcheckParams::gen")]
    pub fn gen(
        bytecode_preprocessing: &BytecodePreprocessing,
        n_cycle_vars: usize,
        one_hot_params: &OneHotParams,
        opening_accumulator: &dyn OpeningAccumulator<F>,
        transcript: &mut impl Transcript,
    ) -> Self {
        let gamma_powers = transcript.challenge_scalar_powers(7);

        let bytecode = &bytecode_preprocessing.bytecode;

        // Generate all stage-specific gamma powers upfront (order must match verifier)
        let stage1_gammas: Vec<F> = transcript.challenge_scalar_powers(2 + NUM_CIRCUIT_FLAGS);
        let stage2_gammas: Vec<F> = transcript.challenge_scalar_powers(5);
        let stage3_gammas: Vec<F> = transcript.challenge_scalar_powers(9);
        let stage4_gammas: Vec<F> = transcript.challenge_scalar_powers(3);
        let stage5_gammas: Vec<F> = transcript.challenge_scalar_powers(2 + NUM_LOOKUP_TABLES);

        // Compute rv_claims (these don't iterate bytecode, just query opening accumulator)
        let rv_claim_1 = Self::compute_rv_claim_1(opening_accumulator, &stage1_gammas);
        let rv_claim_2 = Self::compute_rv_claim_2(opening_accumulator, &stage2_gammas);
        let rv_claim_3 = Self::compute_rv_claim_3(opening_accumulator, &stage3_gammas);
        let rv_claim_4 = Self::compute_rv_claim_4(opening_accumulator, &stage4_gammas);
        let rv_claim_5 = Self::compute_rv_claim_5(opening_accumulator, &stage5_gammas);
        let rv_claims = [rv_claim_1, rv_claim_2, rv_claim_3, rv_claim_4, rv_claim_5];

        // Pre-compute eq_r_register for stages 4 and 5 (they use different r_register points)
        let r_register_4 = opening_accumulator
            .get_virtual_polynomial_opening(
                VirtualPolynomial::RdWa,
                SumcheckId::RegistersReadWriteChecking,
            )
            .0
            .r;
        let eq_r_register_4 =
            EqPolynomial::<F>::evals(&r_register_4[..(REGISTER_COUNT as usize).log_2()]);

        let r_register_5 = opening_accumulator
            .get_virtual_polynomial_opening(
                VirtualPolynomial::RdWa,
                SumcheckId::RegistersValEvaluation,
            )
            .0
            .r;
        let eq_r_register_5 =
            EqPolynomial::<F>::evals(&r_register_5[..(REGISTER_COUNT as usize).log_2()]);

        // Build SymbolicInstruction<F> array: either from thread-local override (symbolic)
        // or by converting concrete Instruction data. Single generic compute_val_polys path.
        let sym_instructions: Vec<SymbolicInstruction<F>> =
            if let Some(pending) = get_pending_bytecode_instructions::<F>() {
                // Capture the concrete eq_r_register tables and gammas for witness fixup.
                set_captured_bytecode_data(CapturedBytecodeData {
                    eq_r_register_4: eq_r_register_4.clone(),
                    eq_r_register_5: eq_r_register_5.clone(),
                    stage5_gammas: stage5_gammas.clone(),
                });
                pending.instructions
            } else {
                bytecode
                    .iter()
                    .map(|instr| {
                        Self::instruction_to_symbolic(
                            instr,
                            &eq_r_register_4,
                            &eq_r_register_5,
                            &stage5_gammas,
                        )
                    })
                    .collect()
            };

        let val_polys = Self::compute_val_polys(
            &sym_instructions,
            &stage1_gammas,
            &stage2_gammas,
            &stage3_gammas,
            &stage4_gammas,
            &stage5_gammas,
        );

        let int_poly = IdentityPolynomial::new(one_hot_params.bytecode_k.log_2());

        let (_, raf_claim) = opening_accumulator
            .get_virtual_polynomial_opening(VirtualPolynomial::PC, SumcheckId::SpartanOuter);
        let (_, raf_shift_claim) = opening_accumulator
            .get_virtual_polynomial_opening(VirtualPolynomial::PC, SumcheckId::SpartanShift);
        let input_claim = [
            rv_claim_1,
            rv_claim_2,
            rv_claim_3,
            rv_claim_4,
            rv_claim_5,
            raf_claim,
            raf_shift_claim,
        ]
        .iter()
        .zip(&gamma_powers)
        .map(|(claim, g)| *claim * g)
        .sum();

        let (r_cycle_1, _) = opening_accumulator
            .get_virtual_polynomial_opening(VirtualPolynomial::Imm, SumcheckId::SpartanOuter);
        let (r_cycle_2, _) = opening_accumulator.get_virtual_polynomial_opening(
            VirtualPolynomial::OpFlags(CircuitFlags::Jump),
            SumcheckId::SpartanProductVirtualization,
        );
        let (r_cycle_3, _) = opening_accumulator.get_virtual_polynomial_opening(
            VirtualPolynomial::UnexpandedPC,
            SumcheckId::SpartanShift,
        );
        let (r, _) = opening_accumulator.get_virtual_polynomial_opening(
            VirtualPolynomial::Rs1Ra,
            SumcheckId::RegistersReadWriteChecking,
        );
        let (_, r_cycle_4) = r.split_at((REGISTER_COUNT as usize).log_2());
        let (r, _) = opening_accumulator.get_virtual_polynomial_opening(
            VirtualPolynomial::RdWa,
            SumcheckId::RegistersValEvaluation,
        );
        let (_, r_cycle_5) = r.split_at((REGISTER_COUNT as usize).log_2());
        let r_cycles = [
            r_cycle_1.r,
            r_cycle_2.r,
            r_cycle_3.r,
            r_cycle_4.r,
            r_cycle_5.r,
        ];

        // Note: We don't have r_address at this point (it comes from sumcheck_challenges),
        // so we initialize r_address_chunks as empty and will compute it later
        Self {
            gamma_powers,
            input_claim,
            one_hot_params: one_hot_params.clone(),
            K: one_hot_params.bytecode_k,
            log_K: one_hot_params.bytecode_k.log_2(),
            d: one_hot_params.bytecode_d,
            log_T: n_cycle_vars,
            val_polys,
            rv_claims,
            raf_claim,
            raf_shift_claim,
            int_poly,
            r_cycles,
        }
    }

    /// Convert a concrete `Instruction` into a `SymbolicInstruction<F>`.
    ///
    /// This is used when there is no symbolic override: concrete instruction data is
    /// converted to field elements so that `compute_val_polys` can use a single generic path.
    /// For `F = Fr`, `flag_var * gamma` is equivalent to `if flag { += gamma }` because
    /// flags are 0 or 1.
    fn instruction_to_symbolic(
        instruction: &Instruction,
        eq_r_register_4: &[F],
        eq_r_register_5: &[F],
        stage5_gammas: &[F],
    ) -> SymbolicInstruction<F> {
        let instr = instruction.normalize();
        let circuit_flags = instruction.circuit_flags();
        let instr_flags = instruction.instruction_flags();

        SymbolicInstruction {
            address: F::from_u64(instr.address as u64),
            imm: F::from_i128(instr.operands.imm),
            circuit_flags: array::from_fn(|i| {
                if circuit_flags[i] { F::one() } else { F::zero() }
            }),
            instruction_flags: array::from_fn(|i| {
                if instr_flags[i] { F::one() } else { F::zero() }
            }),
            eq_r_register_4: [
                instr.operands.rd.map_or(F::zero(), |r| eq_r_register_4[r as usize]),
                instr.operands.rs1.map_or(F::zero(), |r| eq_r_register_4[r as usize]),
                instr.operands.rs2.map_or(F::zero(), |r| eq_r_register_4[r as usize]),
            ],
            eq_r_register_5_rd: instr
                .operands
                .rd
                .map_or(F::zero(), |r| eq_r_register_5[r as usize]),
            stage5_not_interleaved: if circuit_flags.is_interleaved_operands() {
                F::zero()
            } else {
                F::one()
            },
            stage5_lookup_contribution: instruction
                .lookup_table()
                .map_or(F::zero(), |table| stage5_gammas[2 + LookupTables::enum_index(&table)]),
        }
    }

    /// Compute all 5 stage-specific Val(k) polynomials from `SymbolicInstruction<F>`.
    ///
    /// Single generic path: branches like `if flag { lc += gamma }` are replaced by
    /// `flag_var * gamma`. For concrete `F` (flags are 0/1), this is arithmetically
    /// equivalent. For symbolic `F` (MleAst), it produces Mul nodes that yield a
    /// universal circuit structure regardless of program bytecode.
    #[allow(clippy::too_many_arguments)]
    fn compute_val_polys(
        instructions: &[SymbolicInstruction<F>],
        stage1_gammas: &[F],
        stage2_gammas: &[F],
        stage3_gammas: &[F],
        stage4_gammas: &[F],
        stage5_gammas: &[F],
    ) -> [MultilinearPolynomial<F>; N_STAGES] {
        let k = instructions.len();

        let mut vals: [Vec<F>; N_STAGES] = array::from_fn(|_| unsafe_allocate_zero_vec(k));
        let [v0, v1, v2, v3, v4] = &mut vals;

        // Sequential iteration (safe for both Fr and MleAst; K is small enough).
        for (idx, si) in instructions.iter().enumerate() {
            // Stage 1 (Spartan outer sumcheck)
            // Val(k) = address + imm * γ₁ + Σᵢ circuit_flags[i] * γ₂₊ᵢ
            {
                let mut lc = si.address;
                lc = lc + si.imm * stage1_gammas[1];
                for (i, gamma_power) in stage1_gammas[2..].iter().enumerate() {
                    lc = lc + si.circuit_flags[i] * *gamma_power;
                }
                v0[idx] = lc;
            }

            // Stage 2 (product virtualization)
            // Val(k) = cf[Jump]*γ₀ + if[Branch]*γ₁ + if[IsRdNotZero]*γ₂
            //          + cf[WriteLookupOutputToRD]*γ₃ + cf[VirtualInstruction]*γ₄
            {
                let lc = si.circuit_flags[CircuitFlags::Jump as usize] * stage2_gammas[0]
                    + si.instruction_flags[InstructionFlags::Branch as usize] * stage2_gammas[1]
                    + si.instruction_flags[InstructionFlags::IsRdNotZero as usize]
                        * stage2_gammas[2]
                    + si.circuit_flags[CircuitFlags::WriteLookupOutputToRD as usize]
                        * stage2_gammas[3]
                    + si.circuit_flags[CircuitFlags::VirtualInstruction as usize]
                        * stage2_gammas[4];
                v1[idx] = lc;
            }

            // Stage 3 (Shift sumcheck)
            // Val(k) = imm + address*γ₁ + if[LeftOperandIsRs1Value]*γ₂ + if[LeftOperandIsPC]*γ₃
            //          + if[RightOperandIsRs2Value]*γ₄ + if[RightOperandIsImm]*γ₅
            //          + if[IsNoop]*γ₆ + cf[VirtualInstruction]*γ₇ + cf[IsFirstInSequence]*γ₈
            {
                let lc = si.imm
                    + si.address * stage3_gammas[1]
                    + si.instruction_flags[InstructionFlags::LeftOperandIsRs1Value as usize]
                        * stage3_gammas[2]
                    + si.instruction_flags[InstructionFlags::LeftOperandIsPC as usize]
                        * stage3_gammas[3]
                    + si.instruction_flags[InstructionFlags::RightOperandIsRs2Value as usize]
                        * stage3_gammas[4]
                    + si.instruction_flags[InstructionFlags::RightOperandIsImm as usize]
                        * stage3_gammas[5]
                    + si.instruction_flags[InstructionFlags::IsNoop as usize] * stage3_gammas[6]
                    + si.circuit_flags[CircuitFlags::VirtualInstruction as usize]
                        * stage3_gammas[7]
                    + si.circuit_flags[CircuitFlags::IsFirstInSequence as usize]
                        * stage3_gammas[8];
                v2[idx] = lc;
            }

            // Stage 4 (registers read/write checking)
            // Val(k) = rd_eq4 * γ₀ + rs1_eq4 * γ₁ + rs2_eq4 * γ₂
            {
                v3[idx] = si.eq_r_register_4[0] * stage4_gammas[0]
                    + si.eq_r_register_4[1] * stage4_gammas[1]
                    + si.eq_r_register_4[2] * stage4_gammas[2];
            }

            // Stage 5 (registers val-evaluation + instruction lookups)
            // Val(k) = rd_eq5 + not_interleaved * γ₁ + lookup_contribution
            {
                v4[idx] = si.eq_r_register_5_rd
                    + si.stage5_not_interleaved * stage5_gammas[1]
                    + si.stage5_lookup_contribution;
            }
        }

        vals.map(MultilinearPolynomial::from)
    }

    fn compute_rv_claim_1(
        opening_accumulator: &dyn OpeningAccumulator<F>,
        gamma_powers: &[F],
    ) -> F {
        let (_, unexpanded_pc_claim) = opening_accumulator.get_virtual_polynomial_opening(
            VirtualPolynomial::UnexpandedPC,
            SumcheckId::SpartanOuter,
        );
        let (_, imm_claim) = opening_accumulator
            .get_virtual_polynomial_opening(VirtualPolynomial::Imm, SumcheckId::SpartanOuter);

        let circuit_flag_claims: Vec<F> = CircuitFlags::iter()
            .map(|flag| {
                opening_accumulator
                    .get_virtual_polynomial_opening(
                        VirtualPolynomial::OpFlags(flag),
                        SumcheckId::SpartanOuter,
                    )
                    .1
            })
            .collect();

        std::iter::once(unexpanded_pc_claim)
            .chain(std::iter::once(imm_claim))
            .chain(circuit_flag_claims)
            .zip_eq(gamma_powers)
            .map(|(claim, gamma)| claim * gamma)
            .sum()
    }

    fn compute_rv_claim_2(
        opening_accumulator: &dyn OpeningAccumulator<F>,
        gamma_powers: &[F],
    ) -> F {
        let (_, jump_claim) = opening_accumulator.get_virtual_polynomial_opening(
            VirtualPolynomial::OpFlags(CircuitFlags::Jump),
            SumcheckId::SpartanProductVirtualization,
        );
        let (_, branch_claim) = opening_accumulator.get_virtual_polynomial_opening(
            VirtualPolynomial::InstructionFlags(InstructionFlags::Branch),
            SumcheckId::SpartanProductVirtualization,
        );
        let (_, rd_wa_claim) = opening_accumulator.get_virtual_polynomial_opening(
            VirtualPolynomial::InstructionFlags(InstructionFlags::IsRdNotZero),
            SumcheckId::SpartanProductVirtualization,
        );
        let (_, write_lookup_output_to_rd_flag_claim) = opening_accumulator
            .get_virtual_polynomial_opening(
                VirtualPolynomial::OpFlags(CircuitFlags::WriteLookupOutputToRD),
                SumcheckId::SpartanProductVirtualization,
            );
        let (_, virtual_instruction_claim) = opening_accumulator.get_virtual_polynomial_opening(
            VirtualPolynomial::OpFlags(CircuitFlags::VirtualInstruction),
            SumcheckId::SpartanProductVirtualization,
        );

        [
            jump_claim,
            branch_claim,
            rd_wa_claim,
            write_lookup_output_to_rd_flag_claim,
            virtual_instruction_claim,
        ]
        .into_iter()
        .zip_eq(gamma_powers)
        .map(|(claim, gamma)| claim * gamma)
        .sum()
    }

    fn compute_rv_claim_3(
        opening_accumulator: &dyn OpeningAccumulator<F>,
        gamma_powers: &[F],
    ) -> F {
        let (_, imm_claim) = opening_accumulator.get_virtual_polynomial_opening(
            VirtualPolynomial::Imm,
            SumcheckId::InstructionInputVirtualization,
        );
        let (_, spartan_shift_unexpanded_pc_claim) = opening_accumulator
            .get_virtual_polynomial_opening(
                VirtualPolynomial::UnexpandedPC,
                SumcheckId::SpartanShift,
            );
        let (_, instruction_input_unexpanded_pc_claim) = opening_accumulator
            .get_virtual_polynomial_opening(
                VirtualPolynomial::UnexpandedPC,
                SumcheckId::InstructionInputVirtualization,
            );

        assert_eq!(
            spartan_shift_unexpanded_pc_claim,
            instruction_input_unexpanded_pc_claim
        );

        let unexpanded_pc_claim = spartan_shift_unexpanded_pc_claim;
        let (_, left_is_rs1_claim) = opening_accumulator.get_virtual_polynomial_opening(
            VirtualPolynomial::InstructionFlags(InstructionFlags::LeftOperandIsRs1Value),
            SumcheckId::InstructionInputVirtualization,
        );
        let (_, left_is_pc_claim) = opening_accumulator.get_virtual_polynomial_opening(
            VirtualPolynomial::InstructionFlags(InstructionFlags::LeftOperandIsPC),
            SumcheckId::InstructionInputVirtualization,
        );
        let (_, right_is_rs2_claim) = opening_accumulator.get_virtual_polynomial_opening(
            VirtualPolynomial::InstructionFlags(InstructionFlags::RightOperandIsRs2Value),
            SumcheckId::InstructionInputVirtualization,
        );
        let (_, right_is_imm_claim) = opening_accumulator.get_virtual_polynomial_opening(
            VirtualPolynomial::InstructionFlags(InstructionFlags::RightOperandIsImm),
            SumcheckId::InstructionInputVirtualization,
        );
        let (_, is_noop_claim) = opening_accumulator.get_virtual_polynomial_opening(
            VirtualPolynomial::InstructionFlags(InstructionFlags::IsNoop),
            SumcheckId::SpartanShift,
        );
        let (_, is_virtual_claim) = opening_accumulator.get_virtual_polynomial_opening(
            VirtualPolynomial::OpFlags(CircuitFlags::VirtualInstruction),
            SumcheckId::SpartanShift,
        );
        let (_, is_first_in_sequence_claim) = opening_accumulator.get_virtual_polynomial_opening(
            VirtualPolynomial::OpFlags(CircuitFlags::IsFirstInSequence),
            SumcheckId::SpartanShift,
        );

        [
            imm_claim,
            unexpanded_pc_claim,
            left_is_rs1_claim,
            left_is_pc_claim,
            right_is_rs2_claim,
            right_is_imm_claim,
            is_noop_claim,
            is_virtual_claim,
            is_first_in_sequence_claim,
        ]
        .into_iter()
        .zip_eq(gamma_powers)
        .map(|(claim, gamma)| claim * gamma)
        .sum()
    }

    fn compute_rv_claim_4(
        opening_accumulator: &dyn OpeningAccumulator<F>,
        gamma_powers: &[F],
    ) -> F {
        std::iter::empty()
            .chain(once(VirtualPolynomial::RdWa))
            .chain(once(VirtualPolynomial::Rs1Ra))
            .chain(once(VirtualPolynomial::Rs2Ra))
            .map(|vp| {
                opening_accumulator
                    .get_virtual_polynomial_opening(vp, SumcheckId::RegistersReadWriteChecking)
                    .1
            })
            .zip(gamma_powers)
            .map(|(claim, gamma)| claim * gamma)
            .sum::<F>()
    }

    fn compute_rv_claim_5(
        opening_accumulator: &dyn OpeningAccumulator<F>,
        gamma_powers: &[F],
    ) -> F {
        let (_, rd_wa_claim) = opening_accumulator.get_virtual_polynomial_opening(
            VirtualPolynomial::RdWa,
            SumcheckId::RegistersValEvaluation,
        );

        let (_, raf_flag_claim) = opening_accumulator.get_virtual_polynomial_opening(
            VirtualPolynomial::InstructionRafFlag,
            SumcheckId::InstructionReadRaf,
        );

        let mut sum = rd_wa_claim * gamma_powers[0];
        sum += raf_flag_claim * gamma_powers[1];

        // Add lookup table flag claims from InstructionReadRaf
        for i in 0..LookupTables::<XLEN>::COUNT {
            let (_, claim) = opening_accumulator.get_virtual_polynomial_opening(
                VirtualPolynomial::LookupTableFlag(i),
                SumcheckId::InstructionReadRaf,
            );
            sum += claim * gamma_powers[2 + i];
        }

        sum
    }
}

impl<F: JoltField> SumcheckInstanceParams<F> for BytecodeReadRafSumcheckParams<F> {
    fn degree(&self) -> usize {
        self.d + 1
    }

    fn num_rounds(&self) -> usize {
        self.log_K + self.log_T
    }

    fn input_claim(&self, _: &dyn OpeningAccumulator<F>) -> F {
        self.input_claim
    }

    fn normalize_opening_point(
        &self,
        sumcheck_challenges: &[<F as JoltField>::Challenge],
    ) -> OpeningPoint<BIG_ENDIAN, F> {
        let mut r = sumcheck_challenges.to_vec();
        r[0..self.log_K].reverse();
        r[self.log_K..].reverse();
        OpeningPoint::new(r)
    }
}
