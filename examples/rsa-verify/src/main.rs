use jolt_sdk::serialize_and_print_size;
use std::time::Instant;
use tracing::info;

// ── Test vector 1 ─────────────────────────────────────────────────────────────
// RSA-2048 with sig = 2.  expected = 2^65537 mod n.
// n generated with: openssl genrsa 2048 | openssl rsa -noout -modulus
// expected computed with Python: pow(2, 65537, n)

const N1: [u64; 32] = [
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

const SIG1: [u64; 32] = [
    2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0,
];

const EXPECTED1: [u64; 32] = [
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

// ── Test vector 2 ─────────────────────────────────────────────────────────────
// RSA-2048 with sig = 3.  expected = 3^65537 mod n2.
// n2 = 0xBFDCFC0817E81BE7F37BF7FA12FD7103B029583840D8305A030DBCD2793FE1901FB14F0E66EFFEF10010CC0D048A643F5E0955DEA232DA4C16BD5859AB0279044695C3B2CA79719CB246238B843020F59C670D16EACEDA23A89527ACCDB04CD27F00FD7ED076CCB38D388DF513F1A493A3CF95F04BC8A35037AFF49980C5434321AC09330A57B507FB45E207EF5063FA0FE0ED10B4121B970EDE06D5463E74A7A4AB60F7983866C4AED6859DDE67BB5F37CE3226F8E095E5D7BD11DDBB4FCAFEE1B32ED00D58D4F8EFC696AF206E18C725A5F4C780717A6D1018E2011020FE50685507B5572A7B0F24121FF5DDD88B78A5F0E19AB2D85D9668E4C575D2755943

const N2: [u64; 32] = [
    7558383184467286339,
    11957305065210404246,
    2599175075795602296,
    7517923628397787919,
    1159925398241345104,
    2712843488251181677,
    17277662699361016007,
    16263394150476993784,
    15545601132780833534,
    4021206660254045669,
    12598403920703241055,
    11865684259764725444,
    1071301274437055655,
    1144174961348451223,
    18106126400620618746,
    2426324414067356935,
    4012694733137986371,
    11803818007657489232,
    10176039441784743059,
    9151593163922001075,
    12147659193040522450,
    11269990984597821987,
    12845994069246091509,
    5086186526853394844,
    1638562981577128196,
    6776041529047964236,
    4727955910190143,
    2283693409328692977,
    220039568974406032,
    12693774023349776474,
    17544889426784383235,
    13825202067811605479,
];

const SIG2: [u64; 32] = [
    3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0,
];

const EXPECTED2: [u64; 32] = [
    5215271977338411422,
    15640453945200003404,
    15789540900142427428,
    223405004739841330,
    2705503574582460754,
    7892900954273262136,
    2979697287734919038,
    3249406299111795680,
    12165482602804533332,
    7593746141806457535,
    5635231438560583384,
    17187654440290978506,
    12654968920076946844,
    18358769040605384175,
    9362963315017265998,
    8549806294983945817,
    2403734130101520747,
    13496235443503159699,
    11638663132863148346,
    9968064242831299984,
    13751129084039569205,
    2947890600555983003,
    7751268777318696612,
    11727020453913330813,
    7202994396206096848,
    16395178917377985285,
    6919818564134487680,
    13483076318513742284,
    6713393489005873829,
    16145311458901761945,
    13603196888555723877,
    2819924804450884591,
];

pub fn main() {
    tracing_subscriber::fmt::init();

    let args: Vec<String> = std::env::args().collect();
    let save = args.iter().any(|a| a == "--save");
    let vector: u32 = args
        .iter()
        .position(|a| a == "--vector")
        .and_then(|i| args.get(i + 1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(1);
    let force_class: Option<&str> = args
        .iter()
        .position(|a| a == "--class")
        .and_then(|i| args.get(i + 1))
        .map(|s| s.as_str());

    let (n, sig, expected) = match vector {
        1 => (N1, SIG1, EXPECTED1),
        2 => (N2, SIG2, EXPECTED2),
        v => panic!("Unknown test vector {v}. Use --vector 1 or --vector 2."),
    };

    info!("Using test vector {vector} (sig={})", sig[0]);

    let target_dir = "/tmp/jolt-guest-targets";
    let mut program = guest::compile_rsa_verify(target_dir);

    let shared_preprocessing = if let Some(class_name) = force_class {
        use jolt_sdk::{JoltSharedPreprocessing, MemoryConfig, MemoryLayout};
        let class = jolt_sdk::size_class::find_class_by_name(class_name)
            .unwrap_or_else(|| panic!("Unknown size class: {class_name}"));

        let (bytecode, memory_init, program_size, entry_address) = program.decode();
        let memory_config = MemoryConfig {
            max_input_size: 4096,
            max_output_size: 4096,
            max_untrusted_advice_size: 4096,
            max_trusted_advice_size: 4096,
            stack_size: 4096,
            heap_size: 65536,
            program_size: Some(program_size),
        };
        let memory_layout = MemoryLayout::new(&memory_config);

        info!(
            "Forcing size class {} (log_T={}, bytecode_K={}, ram_K={})",
            class.name, class.max_log_t, class.max_bytecode_k, class.max_ram_k
        );
        JoltSharedPreprocessing::new_with_targets(
            bytecode,
            memory_layout,
            memory_init,
            65536,
            entry_address,
            Some(1 << class.max_log_t),
            Some(class.max_ram_k),
            Some(class.max_bytecode_k),
        )
        .unwrap()
    } else {
        guest::preprocess_shared_rsa_verify(&mut program).unwrap()
    };

    let prover_preprocessing = guest::preprocess_prover_rsa_verify(shared_preprocessing.clone());
    let verifier_preprocessing = guest::preprocess_verifier_rsa_verify(
        shared_preprocessing,
        prover_preprocessing.generators.to_verifier_setup(),
        None,
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
    let (output, proof, program_io) = prove(n, sig, expected);
    info!("Prover runtime: {:.2} s", now.elapsed().as_secs_f64());

    let (proof_path, io_path) = match vector {
        1 => ("/tmp/rsa_verify_proof_1.bin", "/tmp/rsa_verify_io_device_1.bin"),
        _ => ("/tmp/rsa_verify_proof_2.bin", "/tmp/rsa_verify_io_device_2.bin"),
    };

    if save {
        serialize_and_print_size("Proof", proof_path, &proof)
            .expect("Could not serialize proof.");
        serialize_and_print_size("io_device", io_path, &program_io)
            .expect("Could not serialize io_device.");
    }

    let is_valid = verify(n, sig, expected, output, program_io.panic, proof);
    info!("rsa_verify(n{vector}, sig={}, expected={}^65537 mod n{vector}): {output}", sig[0], sig[0]);
    info!("proof valid: {is_valid}");
}
