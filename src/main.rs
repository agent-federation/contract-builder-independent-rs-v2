use pap_verifier::package;
use std::env;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    // version/help
    if args.len() == 1 {
        eprintln!("pap: usage: pap verify PACKAGE ...");
        return ExitCode::from(64);
    }
    if args[1] == "--version" {
        let (impl_digest, checker_id, _, _) = pap_verifier::checker::compute();
        println!("pap 0.1.0");
        println!("papVersion support: 0.1");
        println!("reportVersion support: 0.1");
        println!("implementationDigest: {}", impl_digest);
        let _ = checker_id;
        return ExitCode::SUCCESS;
    }
    if args[1] == "--help" {
        println!("pap verify PACKAGE [--trust-policy FILE] [--format text|json] [--now RFC3339]");
        return ExitCode::SUCCESS;
    }

    // command
    let mut i = 1;
    let cmd = args[i].clone();
    i += 1;
    if cmd != "verify" {
        eprintln!("pap: pap.cli.usage: unknown command");
        return ExitCode::from(64);
    }

    // parse options
    let mut package: Option<String> = None;
    let mut _trust_policy: Option<String> = None;
    let mut _format: String = "json".to_string();
    let mut now: Option<String> = None;
    while i < args.len() {
        match args[i].as_str() {
            "--trust-policy" => {
                if i + 1 >= args.len() { eprintln!("pap: pap.cli.usage: missing value"); return ExitCode::from(64); }
                _trust_policy = Some(args[i+1].clone());
                i += 2;
            }
            "--format" => {
                if i + 1 >= args.len() { eprintln!("pap: pap.cli.usage: missing value"); return ExitCode::from(64); }
                _format = args[i+1].clone();
                i += 2;
            }
            "--now" => {
                if i + 1 >= args.len() { eprintln!("pap: pap.cli.usage: missing value"); return ExitCode::from(64); }
                now = Some(args[i+1].clone());
                i += 2;
            }
            s if s.starts_with("--") => {
                eprintln!("pap: pap.cli.usage: unknown option");
                return ExitCode::from(64);
            }
            _ => {
                if package.is_some() {
                    eprintln!("pap: pap.cli.usage: extra positional");
                    return ExitCode::from(64);
                }
                package = Some(args[i].clone());
                i += 1;
            }
        }
    }
    let package = match package {
        Some(p) => p,
        None => { eprintln!("pap: pap.cli.usage: missing package"); return ExitCode::from(64); }
    };

    // resolve root
    let root = match std::fs::canonicalize(&package) {
        Ok(p) => p,
        Err(_) => {
            eprintln!("pap: pap.package.not-found: {}", package);
            return ExitCode::from(74);
        }
    };
    if !root.is_dir() {
        eprintln!("pap: pap.cli.usage: not a directory");
        return ExitCode::from(64);
    }

    let now_str = now.unwrap_or_else(|| "1970-01-01T00:00:00Z".to_string());

    let (report, exit_code) = package::run(&package, &now_str);
    // output
    match serde_json::to_string(&report) {
        Ok(s) => println!("{}", s),
        Err(_) => {
            eprintln!("pap: pap.internal.error: serialization");
            return ExitCode::from(70);
        }
    }
    ExitCode::from(exit_code as u8)
}
