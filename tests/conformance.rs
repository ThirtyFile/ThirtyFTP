//! The conformance tables of the README: every row names tests that exist, so a row can't say "done" for what nothing shows

use std::path::Path;

fn rust_files(directory: &Path, out: &mut Vec<String>) {
    for entry in std::fs::read_dir(directory).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            out.push(std::fs::read_to_string(&path).unwrap());
        }
    }
}

#[test]
fn every_row_of_the_conformance_tables_names_tests_that_exist() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut sources = Vec::new();
    rust_files(&root.join("src"), &mut sources);
    rust_files(&root.join("tests"), &mut sources);
    let sources = sources.join("\n");
    let readme = std::fs::read_to_string(root.join("README.md")).unwrap();

    let mut rows = 0;
    let mut names = 0;
    let mut missing = Vec::new();
    let mut without_tests = Vec::new();
    let mut in_table = false;
    for line in readme.lines() {
        // The tables are under "## Conformance"
        if line.starts_with("## ") {
            in_table = line.starts_with("## Conformance");
        }
        if !in_table || !line.starts_with('|') || line.starts_with("| ---") || line.starts_with("| Requirement") || line.starts_with("| Behaviour") {
            continue;
        }
        let cells: Vec<&str> = line.trim_matches('|').split('|').map(str::trim).collect();
        let tests = cells.last().copied().unwrap_or("");
        let status = if cells.len() >= 4 { cells[2] } else { "" };
        rows += 1;
        let found: Vec<&str> = tests.split('`').skip(1).step_by(2).collect();
        if found.is_empty() {
            // A row without tests says why: it is not something a test can show
            if !(status.starts_with("not applicable") || status.starts_with("not provided")) {
                without_tests.push(cells[0].to_string());
            }
        }
        for name in found {
            names += 1;
            if !sources.contains(&format!("fn {name}(")) {
                missing.push(name.to_string());
            }
        }
    }
    assert!(rows > 30, "the tables were not found: {rows} rows");
    assert!(names > 60, "the test names were not found: {names}");
    assert!(missing.is_empty(), "tests named in the README that don't exist: {missing:?}");
    assert!(without_tests.is_empty(), "rows without tests that are not marked as not applicable or not provided: {without_tests:?}");
}
