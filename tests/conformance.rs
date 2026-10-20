//! The conformance tables (the `conformance` module of the crate documentation): every row names tests that exist, so a row can't say "done" for what
//! nothing shows

use std::path::Path;

fn rust_files(directory: &Path, out: &mut Vec<String>) {
    for entry in std::fs::read_dir(directory).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            out.push(std::fs::read_to_string(&path).unwrap().replace("\r\n", "\n"));
        }
    }
}

/// Whether a file has a test of this name: a function, with the attribute of a test on the line before it, and not ignored
fn has_test(sources: &[String], name: &str) -> bool {
    let signature = format!("fn {name}(");
    sources.iter().any(|source| {
        let lines: Vec<&str> = source.lines().collect();
        lines.iter().enumerate().any(|(index, line)| {
            let declared = line.trim_start().strip_prefix("async ").unwrap_or(line.trim_start()).starts_with(&signature);
            // The attributes above the function, up to the first line that is not one
            let attributes: Vec<&str> = lines[..index].iter().rev().map(|line| line.trim()).take_while(|line| line.starts_with("#[")).collect();
            declared
                && attributes.iter().any(|attribute| *attribute == "#[test]" || attribute.starts_with("#[tokio::test"))
                && !attributes.iter().any(|attribute| attribute.starts_with("#[ignore"))
        })
    })
}

#[test]
fn every_row_of_the_conformance_tables_names_tests_that_exist() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut sources = Vec::new();
    rust_files(&root.join("src"), &mut sources);
    rust_files(&root.join("tests"), &mut sources);
    // The tables are the documentation of a module: the lines start with `//!`
    let page = std::fs::read_to_string(root.join("src").join("conformance.rs")).unwrap().replace("\r\n", "\n");
    let readme: String = page.lines().map(|line| line.strip_prefix("//! ").or_else(|| line.strip_prefix("//!")).unwrap_or(line)).collect::<Vec<_>>().join("\n");

    let mut rows = 0;
    let mut names = 0;
    let mut missing = Vec::new();
    let mut without_tests = Vec::new();
    for line in readme.lines() {
        if !line.starts_with('|') || line.starts_with("| ---") || line.starts_with("| Requirement") || line.starts_with("| Behaviour") {
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
            if !has_test(&sources, name) {
                missing.push(name.to_string());
            }
        }
    }
    assert!(rows > 30, "the tables were not found: {rows} rows");
    assert!(names > 60, "the test names were not found: {names}");
    assert!(missing.is_empty(), "tests named in the README that don't exist, or are not tests, or are ignored: {missing:?}");
    assert!(without_tests.is_empty(), "rows without tests that are not marked as not applicable or not provided: {without_tests:?}");
}

#[test]
fn the_guard_itself_tells_a_test_from_a_function_that_is_not_one() {
    let source = "#[tokio::test]\nasync fn real() {}\n\n#[test]\n#[ignore]\nfn ignored() {}\n\nfn plain() {}\n\n#[tokio::test(start_paused = true)]\nasync fn with_arguments() {}\n".to_string();
    let sources = [source];
    assert!(has_test(&sources, "real"));
    assert!(has_test(&sources, "with_arguments"));
    assert!(!has_test(&sources, "ignored"));
    assert!(!has_test(&sources, "plain"));
    assert!(!has_test(&sources, "rea"));
    assert!(!has_test(&sources, "missing"));
}
