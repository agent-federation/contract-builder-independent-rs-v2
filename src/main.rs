//! `pap` binary entry point (Phase 2a surface: `verify` only).

use pap::checker;
use pap::cli;
use pap::jcs;
use pap::json;
use pap::limits::LimitSet;
use pap::pkg::{self, TerminalError};
use pap::policy;
use std::io::Write;
use std::process::ExitCode;

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let code = run(&argv);
    ExitCode::from(code as u8)
}

fn run(argv: &[String]) -> u32 {
    match execute(argv) {
        Ok(exit) => exit,
        Err(term) => match term {
            TerminalError::Usage(code, message) => {
                eprintln!("pap: {code}: {message}");
                eprintln!("{}", cli::USAGE);
                64
            }
            TerminalError::NotFound => {
                eprintln!("pap: pap.package.not-found: PACKAGE does not exist or does not resolve");
                74
            }
            TerminalError::Io(message) => {
                eprintln!("pap: pap.io.error: {message}");
                74
            }
            TerminalError::Internal(message) => {
                eprintln!("pap: pap.internal.error: {message}");
                70
            }
        },
    }
}

fn execute(argv: &[String]) -> Result<u32, TerminalError> {
    // `--version` and `--help` are outside the minimal Phase 2a surface; any
    // argv that is not exactly a `verify` invocation is a usage error except
    // that a bare `pap` prints the synopsis.
    if argv.is_empty() {
        eprintln!("{}", cli::USAGE);
        return Ok(64);
    }
    let args = match cli::parse_args(argv) {
        Ok(a) => a,
        Err(TerminalError::Usage(code, msg)) => {
            return Err(TerminalError::Usage(code, msg));
        }
        Err(other) => return Err(other),
    };

    // The evaluation clock is fixed before anything else so `--now` is parsed
    // even when the package argument is bad (usage errors have exit priority
    // for option parsing; package resolution errors follow).
    let now = cli::resolve_now(&args.now)?;

    // Trust-policy handling (§6.3.2): an invalid policy fails closed with
    // exit 64 before any package report can be produced.
    let policy = match &args.policy_raw {
        Some(path) => Some(policy::load(path, now)?),
        None => None,
    };

    // Effective limits: defaults, lowered by the policy (never raised).
    let mut limits = LimitSet::defaults();
    if let Some(p) = &policy {
        for (name, value) in p.lowered_limits() {
            let idx = pap::limits::LimitSet::index_of(name).expect("validated name");
            limits.set(idx, *value);
        }
    }

    let input = pkg::VerifyInput {
        package_arg: args.package.clone(),
        limits,
        now,
        policy,
        policy_path: args.policy_path.clone(),
        verifier_id: checker::VERIFIER_ID,
        verifier_version: checker::VERIFIER_VERSION,
        implementation_digest: checker::IMPLEMENTATION_DIGEST,
        checker_identity: checker::CHECKER_IDENTITY,
    };

    let output = pkg::verify(&input)?;

    match args.format {
        cli::OutputFormat::Json => {
            let canonical = jcs::to_canonical(&output.report_json);
            let mut out = std::io::stdout().lock();
            out.write_all(canonical.as_bytes())
                .and_then(|_| out.write_all(b"\n"))
                .and_then(|_| out.flush())
                .map_err(|e| TerminalError::Io(format!("cannot write stdout: {e}")))?;
        }
        cli::OutputFormat::Text => {
            render_text(&output.report_json)
                .map_err(|e| TerminalError::Io(format!("cannot write stdout: {e}")))?;
        }
    }
    Ok(output.exit_code)
}

/// Minimal §9.6-style text rendering (Phase 2a-internal; layout beyond the
/// first lines is non-normative).
fn render_text(report: &json::Json) -> std::io::Result<()> {
    let verdict = report.get("verdict").and_then(|v| v.as_str()).unwrap_or("");
    let mut out = std::io::stdout().lock();
    writeln!(out, "VERDICT: {verdict}")?;
    if verdict != "PASS" {
        writeln!(out, "NOT A PASS — see the report for the deciding dimensions")?;
    }
    if let Some(package) = report.get("package").and_then(|p| p.get("identity")) {
        let identity = package.as_str().unwrap_or("null");
        let pap_version = report
            .get("package")
            .and_then(|p| p.get("papVersion"))
            .and_then(|p| p.as_str())
            .unwrap_or("null");
        writeln!(out, "package: {identity} (papVersion {pap_version})")?;
    }
    if let Some(dims) = report.get("dimensions") {
        let pairs: [(&str, &[&str]); 8] = [
            ("integrity", &["package", "artifacts"]),
            ("sources", &["integrity", "availability"]),
            ("signature", &["validity"]),
            (
                "trust",
                &[
                    "signerIdentity",
                    "policyDecision",
                    "checkerRecognition",
                    "profileRecognition",
                ],
            ),
            ("checks", &[]),
            ("humanReview", &["status"]),
            ("semanticTruth", &[]),
            ("legalEnforceability", &[]),
        ];
        writeln!(out, "dimensions")?;
        for (name, subs) in pairs {
            let value = dims.get(name);
            if name == "checks" {
                if let Some(results) = value.and_then(|c| c.get("results")) {
                    for row in results.as_arr().into_iter().flatten() {
                        let id = row.get("checkId").and_then(|v| v.as_str()).unwrap_or("");
                        let outcome = row.get("outcome").and_then(|v| v.as_str()).unwrap_or("");
                        writeln!(out, "  {id} {outcome}")?;
                    }
                } else {
                    writeln!(out, "  {name} (no rows)")?;
                }
                continue;
            }
            if name == "semanticTruth" || name == "legalEnforceability" {
                let status = value.and_then(|v| v.as_str()).unwrap_or("NOT_EVALUATED");
                writeln!(out, "  {name} {status}")?;
                continue;
            }
            for sub in subs {
                let status = value
                    .and_then(|v| v.get(sub))
                    .and_then(|v| v.as_str())
                    .unwrap_or("NOT_EVALUATED");
                writeln!(out, "  {name}.{sub} {status}")?;
            }
        }
    }
    if let Some(cov) = report.get("coverage") {
        writeln!(out, "coverage: full {}", cov.get("full").and_then(|f| match f {
            pap::json::Json::Bool(b) => Some(if *b { "true" } else { "false" }.to_string()),
            _ => None,
        }).unwrap_or_default())?;
    }
    if let Some(lims) = report.get("limitations").and_then(|l| l.as_arr()) {
        if lims.is_empty() {
            writeln!(out, "limitations: none")?;
        } else {
            writeln!(out, "limitations")?;
            for l in lims {
                let code = l.get("code").and_then(|c| c.as_str()).unwrap_or("");
                let detail = l.get("detail").and_then(|c| c.as_str()).unwrap_or("");
                writeln!(out, "  {code} — {detail}")?;
            }
        }
    }
    out.flush()
}
