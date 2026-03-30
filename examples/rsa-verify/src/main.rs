use jolt_sdk::serialize_and_print_size;
use std::time::Instant;
use tracing::info;

// Test vector: RSA-2048 with sig = 2.
// n is a 2048-bit RSA modulus; expected = 2^65537 mod n.
// All values are little-endian u64 arrays (32 limbs).
//
// Regenerate with:
//   openssl genrsa 2048 | openssl rsa -noout -modulus
// then compute expected = pow(2, 65537, n) in Python.

const N: [u64; 32] = [
    8539000333024762801,
    8257346290471759271,
    1008386439293688159,
    15236584276115680375,
    763411282463038918,
    2699338006098954852,
    6205952863539168085,
    6944402025829471568,
    12389979059405488381,
    886623982514060828,
    11327120918821134017,
    18295431631702006642,
    10992451683846346167,
    11667709148523388534,
    5287080687673633841,
    1572579726999914861,
    7424218908997097127,
    1273372740747908574,
    17247096932799553955,
    17210330523323894489,
    16982725907649005828,
    16569604009945344955,
    7076945015188346728,
    13240496107132952544,
    3066576911830767144,
    11096424762033294262,
    15734402980422381882,
    9548704841954854917,
    2283099123490293044,
    15927783402561277923,
    2085777940652928782,
    14221485793994793152,
];

const SIG: [u64; 32] = [
    2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0,
];

const EXPECTED: [u64; 32] = [
    4242288183757191520,
    12902682169281750927,
    18271072979671955608,
    705150002081551715,
    6882941483358262804,
    14648830260371204145,
    4850112140286336806,
    3942562592068308021,
    554810842179477695,
    16717733628421242098,
    883619017622421322,
    10134833748237202735,
    4274753274445914841,
    7495345032278908041,
    9664766364682396732,
    6146148473845497500,
    1481346348139611829,
    9613391940468945275,
    13331804461747016186,
    338164929844386354,
    7136230065167238162,
    374450182045427940,
    15160642027825682929,
    3597025435694961980,
    8749229670055951947,
    15352352331833618073,
    515893449627874219,
    14407434007533229367,
    6432078039929623028,
    2781616472580360799,
    2348756480351320917,
    8467218100866777461,
];

pub fn main() {
    tracing_subscriber::fmt::init();

    let save = std::env::args().any(|a| a == "--save");

    let target_dir = "/tmp/jolt-guest-targets";
    let mut program = guest::compile_rsa_verify(target_dir);

    let shared_preprocessing = guest::preprocess_shared_rsa_verify(&mut program);
    let prover_preprocessing = guest::preprocess_prover_rsa_verify(shared_preprocessing.clone());
    let verifier_preprocessing = guest::preprocess_verifier_rsa_verify(
        shared_preprocessing,
        prover_preprocessing.generators.to_verifier_setup(),
    );

    if save {
        serialize_and_print_size(
            "Verifier Preprocessing",
            "/tmp/jolt_verifier_preprocessing.dat",
            &verifier_preprocessing,
        )
        .expect("Could not serialize preprocessing.");
    }

    let prove = guest::build_prover_rsa_verify(program, prover_preprocessing);
    let verify = guest::build_verifier_rsa_verify(verifier_preprocessing);

    let now = Instant::now();
    let (output, proof, program_io) = prove(N, SIG, EXPECTED);
    info!("Prover runtime: {:.2} s", now.elapsed().as_secs_f64());

    if save {
        serialize_and_print_size("Proof", "/tmp/rsa_verify_proof.bin", &proof)
            .expect("Could not serialize proof.");
        serialize_and_print_size("io_device", "/tmp/rsa_verify_io_device.bin", &program_io)
            .expect("Could not serialize io_device.");
    }

    let is_valid = verify(N, SIG, EXPECTED, output, program_io.panic, proof);
    info!("rsa_verify(n, sig=2, expected=2^65537 mod n): {output}");
    info!("proof valid: {is_valid}");
}
