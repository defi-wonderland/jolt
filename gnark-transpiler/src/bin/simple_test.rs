//! Simple transpiler test with known inputs and outputs
//!
//! Test 1: Quadratic polynomial
//!   Rust function: quadratic(a, b, c, x) = a + b*x + c*x²
//!   Expected Gnark:
//!     api.Add(api.Add(circuit.X_0, api.Mul(circuit.X_1, circuit.X_3)),
//!             api.Mul(circuit.X_2, api.Mul(circuit.X_3, circuit.X_3)))
//!
//! Test 2: Poseidon hash chain
//!   Rust function: poseidon(poseidon(a, b, c), d, e)
//!   Expected Gnark:
//!     poseidon.Hash(api, poseidon.Hash(api, circuit.X_0, circuit.X_1, circuit.X_2),
//!                   circuit.X_3, circuit.X_4)
//!
//! Test 3: DAG demonstration (shared subexpression)
//!   Rust function: (a + b)² + (a + b) = let t = a + b in t² + t
//!   This demonstrates DAG structure: the (a+b) node has TWO parents
//!   Expected: CSE extracts the shared subexpression

use gnark_transpiler::{generate_gnark_expr, MemoizedCodeGen};
use zklean_extractor::mle_ast::{get_node, Atom, Edge, MleAst, Node};

/// Quadratic polynomial: a + b*x + c*x²
fn quadratic(a: MleAst, b: MleAst, c: MleAst, x: MleAst) -> MleAst {
    let bx = b * x.clone();
    let x_squared = x.clone() * x;
    let cx2 = c * x_squared;
    a + bx + cx2
}

fn main() {
    println!("=== Simple Transpiler Tests ===\n");

    test_quadratic();
    println!("\n{}\n", "=".repeat(60));
    test_poseidon();
    println!("\n{}\n", "=".repeat(60));
    test_dag_sharing();
}

fn test_quadratic() {
    println!("--- Test 1: Quadratic Polynomial ---\n");

    // Create symbolic variables
    let a = MleAst::from_var(0); // circuit.X_0
    let b = MleAst::from_var(1); // circuit.X_1
    let c = MleAst::from_var(2); // circuit.X_2
    let x = MleAst::from_var(3); // circuit.X_3

    // Build AST via Rust function
    let result = quadratic(a, b, c, x);

    println!("1. Rust function:");
    println!("   quadratic(a, b, c, x) = a + b*x + c*x²\n");

    // Print AST structure
    println!("2. AST structure:");
    print_ast(result.root(), 3);
    println!();

    // Generate Gnark expression (without memoization)
    let gnark_expr = generate_gnark_expr(result.root());
    println!("3. Generated Gnark (no memoization):");
    println!("   {}\n", gnark_expr);

    // Generate with memoization
    let mut codegen = MemoizedCodeGen::new();
    codegen.count_refs(result.root());
    let memoized_expr = codegen.generate_expr(result.root());
    let bindings = codegen.bindings_code();

    println!("4. Generated Gnark (with memoization):");
    if !bindings.is_empty() {
        println!("   Bindings:");
        for line in bindings.lines() {
            println!("   {}", line);
        }
    }
    println!("   Expression: {}\n", memoized_expr);

    // Expected output
    println!("5. Expected Gnark:");
    println!("   api.Add(api.Add(circuit.X_0, api.Mul(circuit.X_1, circuit.X_3)), api.Mul(circuit.X_2, api.Mul(circuit.X_3, circuit.X_3)))\n");

    // Verify
    let expected = "api.Add(api.Add(circuit.X_0, api.Mul(circuit.X_1, circuit.X_3)), api.Mul(circuit.X_2, api.Mul(circuit.X_3, circuit.X_3)))";
    if gnark_expr == expected {
        println!("✓ SUCCESS: Generated code matches expected output!");
    } else {
        println!("✗ MISMATCH:");
        println!("  Expected: {}", expected);
        println!("  Got:      {}", gnark_expr);
    }

    // Generate full Go circuit
    let go_circuit =
        generate_simple_circuit(result.root(), "QuadraticCircuit", &bindings, &memoized_expr);
    println!("\n6. Full Go Circuit:");
    println!("{}", go_circuit);

    // Write Go file
    let go_path = "go/quadratic_circuit.go";
    std::fs::write(go_path, &go_circuit).expect("Failed to write Go file");
    println!("   Written to: {}", go_path);

    // Export DOT diagram
    let dot = export_ast_to_dot(result.root(), "quadratic");
    let dot_path = "go/quadratic_ast.dot";
    std::fs::write(dot_path, &dot).expect("Failed to write DOT file");
    println!("\n7. AST exported to: {}", dot_path);
    println!(
        "   Render with: dot -Tsvg {} -o go/quadratic_ast.svg",
        dot_path
    );
}

fn test_poseidon() {
    println!("--- Test 2: Poseidon Hash Chain ---\n");

    // Create symbolic variables
    let a = MleAst::from_var(0); // circuit.X_0
    let b = MleAst::from_var(1); // circuit.X_1
    let c = MleAst::from_var(2); // circuit.X_2
    let d = MleAst::from_var(3); // circuit.X_3
    let e = MleAst::from_var(4); // circuit.X_4

    // Build AST: poseidon(poseidon(a, b, c), d, e)
    let inner_hash = MleAst::poseidon(&a, &b, &c);
    let result = MleAst::poseidon(&inner_hash, &d, &e);

    println!("1. Rust function:");
    println!("   poseidon(poseidon(a, b, c), d, e)\n");

    // Print AST structure
    println!("2. AST structure:");
    print_ast(result.root(), 3);
    println!();

    // Generate Gnark expression (without memoization)
    let gnark_expr = generate_gnark_expr(result.root());
    println!("3. Generated Gnark (no memoization):");
    println!("   {}\n", gnark_expr);

    // Generate with memoization
    let mut codegen = MemoizedCodeGen::new();
    codegen.count_refs(result.root());
    let memoized_expr = codegen.generate_expr(result.root());
    let bindings = codegen.bindings_code();

    println!("4. Generated Gnark (with memoization):");
    if !bindings.is_empty() {
        println!("   Bindings:");
        for line in bindings.lines() {
            println!("   {}", line);
        }
    }
    println!("   Expression: {}\n", memoized_expr);

    // Expected output
    println!("5. Expected Gnark:");
    println!("   poseidon.Hash(api, poseidon.Hash(api, circuit.X_0, circuit.X_1, circuit.X_2), circuit.X_3, circuit.X_4)\n");

    // Verify
    let expected = "poseidon.Hash(api, poseidon.Hash(api, circuit.X_0, circuit.X_1, circuit.X_2), circuit.X_3, circuit.X_4)";
    if gnark_expr == expected {
        println!("✓ SUCCESS: Generated code matches expected output!");
    } else {
        println!("✗ MISMATCH:");
        println!("  Expected: {}", expected);
        println!("  Got:      {}", gnark_expr);
    }

    // Generate full Go circuit
    let go_circuit = generate_simple_circuit(
        result.root(),
        "PoseidonChainCircuit",
        &bindings,
        &memoized_expr,
    );
    println!("\n6. Full Go Circuit:");
    println!("{}", go_circuit);

    // Write Go file
    let go_path = "go/poseidon_chain_circuit.go";
    std::fs::write(go_path, &go_circuit).expect("Failed to write Go file");
    println!("   Written to: {}", go_path);

    // Export DOT diagram
    let dot = export_ast_to_dot(result.root(), "poseidon_chain");
    let dot_path = "go/poseidon_chain_ast.dot";
    std::fs::write(dot_path, &dot).expect("Failed to write DOT file");
    println!("\n7. AST exported to: {}", dot_path);
    println!(
        "   Render with: dot -Tsvg {} -o go/poseidon_chain_ast.svg",
        dot_path
    );
}

fn test_dag_sharing() {
    println!("--- Test 3: DAG Demonstration (Shared Subexpression) ---\n");

    // Create symbolic variables
    let a = MleAst::from_var(0); // circuit.X_0
    let b = MleAst::from_var(1); // circuit.X_1

    // Build AST: (a + b)² + (a + b)
    // The key insight: we use the SAME MleAst handle twice
    let sum = a + b; // This creates ONE node in the arena
    let sum_squared = sum.clone() * sum.clone(); // sum is referenced TWICE here
    let result = sum_squared + sum; // sum is referenced a THIRD time!

    // sum now has 3 parents: two from sum_squared's Mul, one from result's Add
    // This is a DAG, not a tree!

    println!("1. Rust function:");
    println!("   let sum = a + b");
    println!("   let sum_squared = sum * sum");
    println!("   let result = sum_squared + sum");
    println!("   → (a + b)² + (a + b)\n");

    // Print AST structure
    println!("2. AST structure:");
    print_ast(result.root(), 3);
    println!();

    // Count references to demonstrate DAG
    println!("3. Reference count analysis (proves DAG structure):");
    let mut ref_counts = std::collections::HashMap::new();
    count_all_refs(result.root(), &mut ref_counts);

    let mut shared_nodes = vec![];
    for (node_id, count) in &ref_counts {
        if *count > 1 {
            let node = get_node(*node_id);
            shared_nodes.push((*node_id, *count, format!("{:?}", node)));
        }
    }

    if shared_nodes.is_empty() {
        println!("   No shared nodes found (this would be a tree)");
    } else {
        println!("   Shared nodes (ref_count > 1):");
        for (id, count, desc) in &shared_nodes {
            println!("   - Node {}: {} references → {}", id, count, desc);
        }
        println!("\n   ✓ This is a DAG! Node(s) have multiple parents.");
    }
    println!();

    // Generate Gnark expression (without memoization)
    let gnark_expr = generate_gnark_expr(result.root());
    println!("4. Generated Gnark (no memoization - duplicates the shared expr):");
    println!("   {}\n", gnark_expr);

    // Generate with memoization
    let mut codegen = MemoizedCodeGen::new();
    codegen.count_refs(result.root());
    let memoized_expr = codegen.generate_expr(result.root());
    let bindings = codegen.bindings_code();

    println!("5. Generated Gnark (with memoization - extracts shared expr):");
    if !bindings.is_empty() {
        println!("   Bindings:");
        for line in bindings.lines() {
            println!("   {}", line);
        }
    }
    println!("   Expression: {}\n", memoized_expr);

    // Explain the difference
    println!("6. Analysis:");
    println!("   Without CSE: (a+b) is computed 3 times");
    println!("   With CSE:    (a+b) is computed once and reused");
    println!();

    // Generate full Go circuit
    let go_circuit =
        generate_simple_circuit(result.root(), "DAGDemoCircuit", &bindings, &memoized_expr);
    println!("7. Full Go Circuit:");
    println!("{}", go_circuit);

    // Write Go file
    let go_path = "go/dag_demo_circuit.go";
    std::fs::write(go_path, &go_circuit).expect("Failed to write Go file");
    println!("   Written to: {}", go_path);

    // Export DOT diagram - this will show multiple edges pointing to the same node
    let dot = export_ast_to_dot_with_sharing(result.root(), "dag_demo");
    let dot_path = "go/dag_demo_ast.dot";
    std::fs::write(dot_path, &dot).expect("Failed to write DOT file");
    println!("\n8. AST exported to: {}", dot_path);
    println!(
        "   Render with: dot -Tsvg {} -o go/dag_demo_ast.svg",
        dot_path
    );
    println!("   → In the SVG, you'll see multiple arrows pointing to the same node!");
}

/// Count all references to nodes in the AST
fn count_all_refs(node_id: usize, ref_counts: &mut std::collections::HashMap<usize, usize>) {
    let count = ref_counts.entry(node_id).or_insert(0);
    *count += 1;
    if *count > 1 {
        return; // Already counted children
    }

    let node = get_node(node_id);
    match node {
        Node::Atom(_) => {}
        Node::Add(e1, e2) | Node::Mul(e1, e2) | Node::Sub(e1, e2) | Node::Div(e1, e2) => {
            count_refs_from_edge(&e1, ref_counts);
            count_refs_from_edge(&e2, ref_counts);
        }
        Node::Neg(e) | Node::Inv(e) | Node::Keccak256(e) => {
            count_refs_from_edge(&e, ref_counts);
        }
        Node::Poseidon(e1, e2, e3) => {
            count_refs_from_edge(&e1, ref_counts);
            count_refs_from_edge(&e2, ref_counts);
            count_refs_from_edge(&e3, ref_counts);
        }
    }
}

fn count_refs_from_edge(edge: &Edge, ref_counts: &mut std::collections::HashMap<usize, usize>) {
    if let Edge::NodeRef(id) = edge {
        count_all_refs(*id, ref_counts);
    }
}

/// Export AST to DOT format, highlighting shared nodes
fn export_ast_to_dot_with_sharing(root: usize, name: &str) -> String {
    // First, count references
    let mut ref_counts = std::collections::HashMap::new();
    count_all_refs(root, &mut ref_counts);

    let mut dot = String::new();
    dot.push_str(&format!("digraph {} {{\n", name));
    dot.push_str("  rankdir=TB;\n");
    dot.push_str("  node [shape=box, fontname=\"monospace\"];\n\n");

    // Collect all reachable nodes
    let mut visited = std::collections::HashSet::new();
    let mut stack = vec![root];

    while let Some(node_id) = stack.pop() {
        if visited.contains(&node_id) {
            continue;
        }
        visited.insert(node_id);

        let node = get_node(node_id);
        let ref_count = ref_counts.get(&node_id).unwrap_or(&1);
        let is_shared = *ref_count > 1;

        let (label, base_color, children) = match &node {
            Node::Atom(Atom::Var(v)) => (format!("X_{}", v), "lightblue", vec![]),
            Node::Atom(Atom::Scalar(s)) => (format!("{}", s), "lightgray", vec![]),
            Node::Atom(Atom::NamedVar(idx)) => (format!("cse_{}", idx), "lightcyan", vec![]),
            Node::Add(e1, e2) => ("Add".to_string(), "lightyellow", get_edge_children(e1, e2)),
            Node::Mul(e1, e2) => ("Mul".to_string(), "lightgreen", get_edge_children(e1, e2)),
            Node::Sub(e1, e2) => ("Sub".to_string(), "lightpink", get_edge_children(e1, e2)),
            Node::Div(e1, e2) => ("Div".to_string(), "lightsalmon", get_edge_children(e1, e2)),
            Node::Neg(e) => ("Neg".to_string(), "white", get_single_edge_child(e)),
            Node::Inv(e) => ("Inv".to_string(), "white", get_single_edge_child(e)),
            Node::Poseidon(e1, e2, e3) => (
                "Poseidon".to_string(),
                "orange",
                get_poseidon_children(e1, e2, e3),
            ),
            Node::Keccak256(e) => ("Keccak".to_string(), "purple", get_single_edge_child(e)),
        };

        // Highlight shared nodes with red border and show ref count
        let color = if is_shared { "red" } else { base_color };
        let penwidth = if is_shared { "3" } else { "1" };
        let label_with_refs = if is_shared {
            format!("[{}] {}\\n(refs: {})", node_id, label, ref_count)
        } else {
            format!("[{}] {}", node_id, label)
        };

        dot.push_str(&format!(
            "  n{} [label=\"{}\" style=filled fillcolor=\"{}\" color=\"{}\" penwidth={}];\n",
            node_id, label_with_refs, base_color, color, penwidth
        ));

        for child_id in &children {
            stack.push(*child_id);
            // Highlight edges to shared nodes
            let child_shared = ref_counts.get(child_id).unwrap_or(&1) > &1;
            if child_shared {
                dot.push_str(&format!(
                    "  n{} -> n{} [color=red penwidth=2];\n",
                    node_id, child_id
                ));
            } else {
                dot.push_str(&format!("  n{} -> n{};\n", node_id, child_id));
            }
        }
    }

    dot.push_str("}\n");
    dot
}

/// Generate a simple Go circuit from a single expression
fn generate_simple_circuit(root: usize, name: &str, bindings: &str, expr: &str) -> String {
    // Collect variables used
    let mut vars = std::collections::BTreeSet::new();
    collect_vars(root, &mut vars);

    let mut output = String::new();
    output.push_str("package jolt_verifier\n\n");
    output.push_str("import (\n");
    output.push_str("\t\"github.com/consensys/gnark/frontend\"\n");
    if bindings.contains("poseidon.Hash") || expr.contains("poseidon.Hash") {
        output.push_str("\t\"github.com/vocdoni/gnark-prover-tinygo/std/hash/poseidon\"\n");
    }
    output.push_str(")\n\n");

    // Circuit struct
    output.push_str(&format!("type {} struct {{\n", name));
    for var in &vars {
        output.push_str(&format!(
            "\tX_{} frontend.Variable `gnark:\",public\"`\n",
            var
        ));
    }
    output.push_str("\tExpectedResult frontend.Variable `gnark:\",public\"`\n");
    output.push_str("}\n\n");

    // Define method
    output.push_str(&format!(
        "func (circuit *{}) Define(api frontend.API) error {{\n",
        name
    ));

    // Add bindings if any
    if !bindings.is_empty() {
        output.push_str("\t// Memoized subexpressions\n");
        for line in bindings.lines() {
            output.push_str(&format!("\t{}\n", line));
        }
        output.push_str("\n");
    }

    // Final expression
    output.push_str(&format!("\tresult := {}\n", expr));
    output.push_str("\tapi.AssertIsEqual(result, circuit.ExpectedResult)\n\n");
    output.push_str("\treturn nil\n");
    output.push_str("}\n");

    output
}

/// Collect all variable indices used in an AST
fn collect_vars(node_id: usize, vars: &mut std::collections::BTreeSet<u16>) {
    let node = get_node(node_id);
    match node {
        Node::Atom(Atom::Var(v)) => {
            vars.insert(v);
        }
        Node::Atom(_) => {}
        Node::Add(e1, e2) | Node::Mul(e1, e2) | Node::Sub(e1, e2) | Node::Div(e1, e2) => {
            collect_vars_from_edge(&e1, vars);
            collect_vars_from_edge(&e2, vars);
        }
        Node::Neg(e) | Node::Inv(e) | Node::Keccak256(e) => {
            collect_vars_from_edge(&e, vars);
        }
        Node::Poseidon(e1, e2, e3) => {
            collect_vars_from_edge(&e1, vars);
            collect_vars_from_edge(&e2, vars);
            collect_vars_from_edge(&e3, vars);
        }
    }
}

fn collect_vars_from_edge(edge: &Edge, vars: &mut std::collections::BTreeSet<u16>) {
    match edge {
        Edge::NodeRef(id) => collect_vars(*id, vars),
        Edge::Atom(Atom::Var(v)) => {
            vars.insert(*v);
        }
        Edge::Atom(_) => {}
    }
}

/// Export AST to DOT format for visualization
fn export_ast_to_dot(root: usize, name: &str) -> String {
    let mut dot = String::new();
    dot.push_str(&format!("digraph {} {{\n", name));
    dot.push_str("  rankdir=TB;\n");
    dot.push_str("  node [shape=box, fontname=\"monospace\"];\n\n");

    // Collect all reachable nodes
    let mut visited = std::collections::HashSet::new();
    let mut stack = vec![root];

    while let Some(node_id) = stack.pop() {
        if visited.contains(&node_id) {
            continue;
        }
        visited.insert(node_id);

        let node = get_node(node_id);
        let (label, color, children) = match &node {
            Node::Atom(Atom::Var(v)) => (format!("X_{}", v), "lightblue", vec![]),
            Node::Atom(Atom::Scalar(s)) => (format!("{}", s), "lightgray", vec![]),
            Node::Atom(Atom::NamedVar(idx)) => (format!("cse_{}", idx), "lightcyan", vec![]),
            Node::Add(e1, e2) => ("Add".to_string(), "lightyellow", get_edge_children(e1, e2)),
            Node::Mul(e1, e2) => ("Mul".to_string(), "lightgreen", get_edge_children(e1, e2)),
            Node::Sub(e1, e2) => ("Sub".to_string(), "lightpink", get_edge_children(e1, e2)),
            Node::Div(e1, e2) => ("Div".to_string(), "lightsalmon", get_edge_children(e1, e2)),
            Node::Neg(e) => ("Neg".to_string(), "white", get_single_edge_child(e)),
            Node::Inv(e) => ("Inv".to_string(), "white", get_single_edge_child(e)),
            Node::Poseidon(e1, e2, e3) => (
                "Poseidon".to_string(),
                "orange",
                get_poseidon_children(e1, e2, e3),
            ),
            Node::Keccak256(e) => ("Keccak".to_string(), "purple", get_single_edge_child(e)),
        };

        dot.push_str(&format!(
            "  n{} [label=\"[{}] {}\" style=filled fillcolor=\"{}\"];\n",
            node_id, node_id, label, color
        ));

        for child_id in &children {
            stack.push(*child_id);
            dot.push_str(&format!("  n{} -> n{};\n", node_id, child_id));
        }
    }

    dot.push_str("}\n");
    dot
}

fn get_edge_children(e1: &Edge, e2: &Edge) -> Vec<usize> {
    let mut children = vec![];
    if let Edge::NodeRef(id) = e1 {
        children.push(*id);
    }
    if let Edge::NodeRef(id) = e2 {
        children.push(*id);
    }
    children
}

fn get_single_edge_child(e: &Edge) -> Vec<usize> {
    if let Edge::NodeRef(id) = e {
        vec![*id]
    } else {
        vec![]
    }
}

fn get_poseidon_children(e1: &Edge, e2: &Edge, e3: &Edge) -> Vec<usize> {
    let mut children = vec![];
    if let Edge::NodeRef(id) = e1 {
        children.push(*id);
    }
    if let Edge::NodeRef(id) = e2 {
        children.push(*id);
    }
    if let Edge::NodeRef(id) = e3 {
        children.push(*id);
    }
    children
}

fn print_ast(node_id: usize, indent: usize) {
    let node = zklean_extractor::mle_ast::get_node(node_id);
    let spaces = " ".repeat(indent);

    match node {
        zklean_extractor::mle_ast::Node::Atom(atom) => {
            println!("{}{:?}", spaces, atom);
        }
        zklean_extractor::mle_ast::Node::Add(e1, e2) => {
            println!("{}Add(", spaces);
            print_edge(&e1, indent + 2);
            print_edge(&e2, indent + 2);
            println!("{})", spaces);
        }
        zklean_extractor::mle_ast::Node::Mul(e1, e2) => {
            println!("{}Mul(", spaces);
            print_edge(&e1, indent + 2);
            print_edge(&e2, indent + 2);
            println!("{})", spaces);
        }
        zklean_extractor::mle_ast::Node::Sub(e1, e2) => {
            println!("{}Sub(", spaces);
            print_edge(&e1, indent + 2);
            print_edge(&e2, indent + 2);
            println!("{})", spaces);
        }
        zklean_extractor::mle_ast::Node::Poseidon(e1, e2, e3) => {
            println!("{}Poseidon(", spaces);
            print_edge(&e1, indent + 2);
            print_edge(&e2, indent + 2);
            print_edge(&e3, indent + 2);
            println!("{})", spaces);
        }
        _ => println!("{}{:?}", spaces, node),
    }
}

fn print_edge(edge: &zklean_extractor::mle_ast::Edge, indent: usize) {
    match edge {
        zklean_extractor::mle_ast::Edge::NodeRef(id) => print_ast(*id, indent),
        zklean_extractor::mle_ast::Edge::Atom(atom) => {
            println!("{}{:?}", " ".repeat(indent), atom);
        }
    }
}
