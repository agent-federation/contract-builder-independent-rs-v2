//! Minimal Phase 2a CLI: `pap verify PACKAGE [--trust-policy FILE]
//! [--format text|json] [--now RFC3339]`.
//!
//! The complete public CLI contract (`inspect`, `explain`, text/JSON stream
//! behaviour) is Phase 2c scope. This interface implements the smallest
//! surface necessary to run the Phase 2a verifier and its tests, as allowed
//! by brief §4.7: exactly the `verify` command, `--format json` only as the
//! machine-readable path, with §9.7 exit codes and stream discipline
//! (stderr empty for report exits; usage/policy errors exit 64 with a stderr
//! code; a missing PACKAGE exits 74).

use crate::pkg::TerminalError;
use crate::rfc3339::Instant;

pub const USAGE: &str = "usage: pap verify PACKAGE [--trust-policy FILE] [--format text|json] [--now RFC3339]";

pub struct VerifyArgs {
    pub package: String,
    pub policy_path: Option<String>,
    pub policy_raw: Option<std::path::PathBuf>,
    pub format: OutputFormat,
    pub now: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Text,
    Json,
}

/// Parse argv (after the binary name). Returns usage errors as TerminalError.
pub fn parse_args(argv: &[String]) -> Result<VerifyArgs, TerminalError> {
    if argv.is_empty() {
        return Err(TerminalError::Usage("pap.cli.usage", "missing command".to_string()));
    }
    if argv[0] != "verify" {
        return Err(TerminalError::Usage(
            "pap.cli.usage",
            format!("unknown command {:?} (Phase 2a implements `verify` only)", argv[0]),
        ));
    }
    let mut package: Option<String> = None;
    let mut policy_path: Option<String> = None;
    let mut policy_raw: Option<std::path::PathBuf> = None;
    let mut format = OutputFormat::Text;
    let mut now: Option<String> = None;
    let mut seen_policy = false;
    let mut seen_format: Option<OutputFormat> = None;
    let mut seen_now = false;

    let mut i = 1;
    // `--` ends option parsing so a path may start with `-`.
    let mut end_of_options = false;
    while i < argv.len() {
        let arg = argv[i].clone();
        if !end_of_options && arg == "--" {
            end_of_options = true;
            i += 1;
            continue;
        }
        if !end_of_options && arg.starts_with("--") {
            let (name, inline) = match arg.split_once('=') {
                Some((n, v)) => (n.to_string(), Some(v.to_string())),
                None => (arg.clone(), None),
            };
            macro_rules! take_value {
                () => {{
                    match inline.clone() {
                        Some(v) => v,
                        None => {
                            if i + 1 >= argv.len() {
                                return Err(TerminalError::Usage(
                                    "pap.cli.usage",
                                    format!("{name} requires a value"),
                                ));
                            }
                            i += 1;
                            argv[i].clone()
                        }
                    }
                }};
            }
            match name.as_str() {
                "--trust-policy" => {
                    if seen_policy || inline.is_some() && seen_policy {
                        return Err(TerminalError::Usage(
                            "pap.cli.usage",
                            "repeated --trust-policy option".to_string(),
                        ));
                    }
                    let v = take_value!();
                    if inline.is_some() {
                        seen_policy = true;
                    } else {
                        seen_policy = true;
                    }
                    let path = std::path::PathBuf::from(&v);
                    policy_path = Some(v);
                    policy_raw = Some(path);
                }
                "--format" => {
                    let v = take_value!();
                    let f = match v.as_str() {
                        "text" => OutputFormat::Text,
                        "json" => OutputFormat::Json,
                        _ => {
                            return Err(TerminalError::Usage(
                                "pap.cli.usage",
                                format!("invalid --format value: {v}"),
                            ))
                        }
                    };
                    if seen_format.is_some() {
                        return Err(TerminalError::Usage(
                            "pap.cli.usage",
                            "repeated --format option".to_string(),
                        ));
                    }
                    seen_format = Some(f);
                    format = f;
                }
                "--now" => {
                    let v = take_value!();
                    if seen_now {
                        return Err(TerminalError::Usage(
                            "pap.cli.usage",
                            "repeated --now option".to_string(),
                        ));
                    }
                    seen_now = true;
                    now = Some(v);
                }
                _ => {
                    return Err(TerminalError::Usage(
                        "pap.cli.usage",
                        format!("unknown option {name}"),
                    ));
                }
            }
            i += 1;
            continue;
        }
        if !end_of_options && arg.starts_with('-') && arg != "-" {
            return Err(TerminalError::Usage(
                "pap.cli.usage",
                format!("unknown option {arg}"),
            ));
        }
        if package.is_some() {
            return Err(TerminalError::Usage(
                "pap.cli.usage",
                "more than one positional PACKAGE argument".to_string(),
            ));
        }
        package = Some(arg.clone());
        i += 1;
    }
    let package = match package {
        Some(p) => p,
        None => {
            return Err(TerminalError::Usage(
                "pap.cli.usage",
                "missing PACKAGE positional argument".to_string(),
            ))
        }
    };
    if package.is_empty() {
        return Err(TerminalError::Usage(
            "pap.cli.usage",
            "empty PACKAGE argument".to_string(),
        ));
    }
    Ok(VerifyArgs {
        package,
        policy_path,
        policy_raw,
        format,
        now,
    })
}

/// Local evaluation clock: `--now` when supplied, else the system clock read
/// once per run. Unparsable `--now` values are usage errors (§9.8).
pub fn resolve_now(now_arg: &Option<String>) -> Result<Instant, TerminalError> {
    match now_arg {
        Some(text) => {
            let t = crate::rfc3339::parse(text).ok_or_else(|| {
                TerminalError::Usage(
                    "pap.cli.usage",
                    format!("--now must be an RFC 3339 date-time: {text}"),
                )
            })?;
            Ok(t)
        }
        None => Ok(Instant::from_system_time(std::time::SystemTime::now())),
    }
}

/// Normalized UTC rendering of the evaluation instant (§9.8).
pub fn evaluated_at(now: Instant) -> String {
    crate::rfc3339::format(now)
}
