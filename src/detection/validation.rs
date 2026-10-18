use super::*;
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

pub fn sha256(value: &str) -> bool {
    hex(value, 64)
}
pub fn hex(value: &str, length: usize) -> bool {
    value.len() == length && value.bytes().all(|b| b.is_ascii_hexdigit())
}
pub fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 160
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
}
pub fn relative_path(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 1024
        && !value.contains(['\\', ':'])
        && !value.chars().any(char::is_control)
        && value.split('/').all(|p| {
            !p.is_empty() && p != "." && p != ".." && !p.ends_with([' ', '.']) && !windows_device(p)
        })
}
fn windows_device(component: &str) -> bool {
    let stem = component
        .split('.')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    ["con", "prn", "aux", "nul"].contains(&stem.as_str())
        || (stem.len() == 4
            && (stem.starts_with("com") || stem.starts_with("lpt"))
            && stem.as_bytes()[3].is_ascii_digit())
}

/// Reject duplicate JSON keys, oversized structures, and deep recursion *during* parsing.
struct BoundedValue<'a> {
    limits: &'a Limits,
    depth: usize,
    nodes: &'a mut usize,
}
impl<'de> DeserializeSeed<'de> for BoundedValue<'_> {
    type Value = Value;
    fn deserialize<D: de::Deserializer<'de>>(self, d: D) -> Result<Value, D::Error> {
        if self.depth > self.limits.depth || *self.nodes > self.limits.output_bytes as usize / 2 {
            return Err(de::Error::custom("JSON structural budget exceeded"));
        }
        *self.nodes += 1;
        d.deserialize_any(self)
    }
}
impl<'de> Visitor<'de> for BoundedValue<'_> {
    type Value = Value;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("bounded JSON")
    }
    fn visit_bool<E: de::Error>(self, v: bool) -> Result<Value, E> {
        Ok(Value::Bool(v))
    }
    fn visit_i64<E: de::Error>(self, v: i64) -> Result<Value, E> {
        Ok(v.into())
    }
    fn visit_u64<E: de::Error>(self, v: u64) -> Result<Value, E> {
        Ok(v.into())
    }
    fn visit_f64<E: de::Error>(self, v: f64) -> Result<Value, E> {
        serde_json::Number::from_f64(v)
            .map(Value::Number)
            .ok_or_else(|| E::custom("nonfinite number"))
    }
    fn visit_unit<E: de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_str<E: de::Error>(self, v: &str) -> Result<Value, E> {
        if v.len() > self.limits.string_bytes {
            return Err(E::custom("string budget exceeded"));
        }
        Ok(Value::String(v.into()))
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let mut values = vec![];
        while let Some(value) = seq.next_element_seed(BoundedValue {
            limits: self.limits,
            depth: self.depth + 1,
            nodes: self.nodes,
        })? {
            if values.len()
                >= self
                    .limits
                    .packets
                    .max(self.limits.strings)
                    .max(self.limits.findings)
            {
                return Err(de::Error::custom("array budget exceeded"));
            }
            values.push(value);
        }
        Ok(Value::Array(values))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut values = serde_json::Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if key.len() > self.limits.string_bytes
                || values.len() >= self.limits.features
                || values.contains_key(&key)
            {
                return Err(de::Error::custom("duplicate key or map budget exceeded"));
            }
            let value = map.next_value_seed(BoundedValue {
                limits: self.limits,
                depth: self.depth + 1,
                nodes: self.nodes,
            })?;
            values.insert(key, value);
        }
        Ok(Value::Object(values))
    }
}
pub fn bounded_json(bytes: &[u8], limits: &Limits) -> Result<Value, &'static str> {
    limits.validate()?;
    if bytes.len() as u64 > limits.output_bytes {
        return Err("output byte limit exceeded");
    }
    let mut nodes = 0;
    let mut de = serde_json::Deserializer::from_slice(bytes);
    let result = BoundedValue {
        limits,
        depth: 0,
        nodes: &mut nodes,
    }
    .deserialize(&mut de)
    .map_err(|_| "malformed or unbounded JSON")?;
    de.end().map_err(|_| "trailing JSON")?;
    Ok(result)
}

pub struct TrustedTarget<'a> {
    pub id: &'a str,
    pub sha256: &'a str,
    pub size: u64,
}

/// Scanner paths and hashes are assertions, never authority to open files.
pub fn parse_result(
    bytes: &[u8],
    expected_scanner: &str,
    target: TrustedTarget<'_>,
    config: &ScannerConfig,
    evidence: &BTreeSet<String>,
) -> Result<ScannerResult, &'static str> {
    let mut result: ScannerResult = serde_json::from_value(bounded_json(bytes, &config.limits)?)
        .map_err(|_| "unsupported scanner schema")?;
    if result.schema_version != 1 || result.scanner != expected_scanner {
        return Err("unsupported scanner schema");
    }
    let expected_version = match expected_scanner {
        "yara" => YARA_VERSION,
        "pe" => PE_VERSION,
        "capa" => CAPA_VERSION,
        "network" => PACKET_VERSION,
        _ => return Err("unknown scanner"),
    };
    if result.version != expected_version {
        return Err("unsupported engine version");
    }
    if !sha256(&result.target_sha256)
        || !sha256(target.sha256)
        || !result.target_sha256.eq_ignore_ascii_case(target.sha256)
        || result.target != target.id
    {
        return Err("scanner target identity mismatch");
    }
    if result.target != "primary" && !relative_path(&result.target) {
        return Err("invalid target path");
    }
    if result.limits != config.limits {
        return Err("scanner changed resource limits");
    }
    if (expected_scanner != "network" && !result.packets.is_empty())
        || (expected_scanner != "pe" && !result.strings.is_empty())
    {
        return Err("scanner supplied data belonging to another stage");
    }
    if result.rule_packs.len() > 2
        || result.warnings.len() > 64
        || result.findings.len() > config.limits.findings
        || result.strings.len() > config.limits.strings
        || result.packets.len() > config.limits.packets
    {
        return Err("result count limit exceeded");
    }
    if result.status == Status::Completed && (result.truncated || !result.warnings.is_empty()) {
        return Err("complete result contains incomplete coverage");
    }
    if !matches!(result.status, Status::Completed | Status::Disabled) && result.warnings.is_empty()
    {
        return Err("incomplete result omitted warning");
    }
    if let (Some(start), Some(end)) = (result.started_at_ms, result.completed_at_ms)
        && end < start
    {
        return Err("invalid scanner timestamps");
    }
    let mut packs = BTreeSet::new();
    for pack in &result.rule_packs {
        let configured = if pack.trusted {
            &config.rules
        } else {
            &config.user_rules
        };
        if !packs.insert(pack.id.clone())
            || !sha256(&pack.sha256)
            || configured.as_ref().is_none_or(|p| {
                p.id != pack.id
                    || p.version != pack.version
                    || !p.sha256.eq_ignore_ascii_case(&pack.sha256)
            })
        {
            return Err("rule-pack identity mismatch");
        }
    }
    if matches!(expected_scanner, "yara" | "capa" | "network")
        && (result.status == Status::Completed
            || !result.findings.is_empty()
            || !result.packets.is_empty())
        && config.rules.as_ref().is_none_or(|p| !packs.contains(&p.id))
    {
        return Err("missing verified built-in rule pack");
    }
    resolve(&result.evidence_ids, evidence)?;
    // Importers assign the retained output path after validating its manifest; scanners cannot.
    if result.original.is_some() {
        return Err("scanner cannot nominate a retained host artifact");
    }
    let mut ids = BTreeSet::new();
    for finding in &mut result.findings {
        if !identifier(&finding.id) || !ids.insert(finding.id.clone()) {
            return Err("duplicate or invalid finding ID");
        }
        if !packs.contains(&finding.rule_pack) || finding.rule.is_empty() {
            return Err("unknown rule pack or empty rule");
        }
        if finding.locations.len() > config.limits.offsets
            || finding.features.len() > config.limits.features
            || finding.tags.len() > 64
            || finding.attack.len() > 64
            || finding.mbc.len() > 64
            || finding.metadata.len() > 64
            || finding.maec.len() > 64
        {
            return Err("finding limit exceeded");
        }
        for loc in &finding.locations {
            if ![
                "file",
                "absolute",
                "relative",
                "function",
                "basic_block",
                "instruction",
                "packet",
            ]
            .contains(&loc.kind.as_str())
                || loc.excerpt_hex.len() > config.limits.match_bytes * 2
                || !hex(&loc.excerpt_hex, loc.excerpt_hex.len())
                || loc.excerpt_hex.len() % 2 != 0
                || loc.excerpt_hex.len() as u64 / 2 > loc.length
                || (loc.kind == "file"
                    && loc
                        .offset
                        .checked_add(loc.length)
                        .is_none_or(|end| end > target.size))
            {
                return Err("invalid match offset or excerpt");
            }
        }
        resolve(&finding.evidence_ids, evidence)?;
        finding.locations.sort();
        finding.locations.dedup();
        finding.features.sort();
        finding.features.dedup();
        finding.tags.sort();
        finding.tags.dedup();
        finding.attack.sort();
        finding.attack.dedup();
        finding.mbc.sort();
        finding.mbc.dedup();
    }
    for s in &result.strings {
        if s.offset.is_some_and(|offset| offset >= target.size)
            || !["ascii", "utf16le", "base64", "xor"].contains(&s.method.as_str())
        {
            return Err("invalid extracted string");
        }
    }
    if let Some(pe) = &result.pe {
        if expected_scanner != "pe"
            || pe.sections.len() > 96
            || pe.imports.len() > config.limits.features
            || pe.exports.len() > config.limits.features
            || pe.resources.len() > config.limits.features
            || pe.debug.len() > 64
            || pe.certificates.len() > 16
            || pe.tls_callbacks.len() > config.limits.offsets
            || pe.embedded_pe_offsets.len() > config.limits.offsets
            || pe.overlay_size > target.size
        {
            return Err("invalid PE metadata limits");
        }
        for section in &pe.sections {
            if !sha256(&section.sha256)
                || !section.entropy.is_finite()
                || !(0.0..=8.0).contains(&section.entropy)
                || section
                    .offset
                    .checked_add(section.raw_size)
                    .is_none_or(|end| end > target.size)
            {
                return Err("invalid PE section");
            }
        }
        if pe.imphash.as_ref().is_some_and(|h| !hex(h, 32))
            || pe.authentihash.as_ref().is_some_and(|h| !sha256(h))
            || pe
                .certificates
                .iter()
                .any(|c| c.get("sha256").is_some_and(|h| !sha256(h)))
        {
            return Err("invalid PE digest");
        }
    }
    let mut flows = BTreeSet::new();
    for packet in &result.packets {
        if !identifier(&packet.id)
            || !ids.insert(packet.id.clone())
            || !identifier(&packet.flow)
            || packet.packet == 0
            || packet.packet > config.limits.packets as u64
            || packet.source.parse::<std::net::IpAddr>().is_err()
            || packet.destination.parse::<std::net::IpAddr>().is_err()
            || packet.dns_answers.len() > 64
            || packet
                .tls
                .get("certificate_sha256")
                .is_some_and(|h| !sha256(h))
            || packet
                .dns_answers
                .iter()
                .any(|s| s.parse::<std::net::IpAddr>().is_err())
        {
            return Err("invalid packet observation");
        }
        flows.insert(&packet.flow);
        resolve(&packet.evidence_ids, evidence)?;
    }
    if flows.len() > config.limits.flows {
        return Err("flow limit exceeded");
    }
    result.target_sha256 = target.sha256.to_ascii_lowercase();
    result.strings.sort();
    result.strings.dedup();
    result
        .packets
        .sort_by(|a, b| (a.timestamp_us, a.packet, &a.id).cmp(&(b.timestamp_us, b.packet, &b.id)));
    result.rule_packs.sort_by(|a, b| a.id.cmp(&b.id));
    // Volatile wall times remain in the hashed raw artifact. Deterministic reports omit them.
    result.started_at_ms = None;
    result.completed_at_ms = None;
    result.duration_ms = None;
    deduplicate_findings(&mut result.findings, &config.limits)?;
    Ok(result)
}
pub fn resolve(ids: &[String], available: &BTreeSet<String>) -> Result<(), &'static str> {
    if ids.len() > 1024 || ids.is_empty() {
        return Err("missing or excessive evidence references");
    }
    let mut seen = BTreeSet::new();
    for id in ids {
        if !available.contains(id) || !seen.insert(id) {
            return Err("unresolved or duplicate evidence reference");
        }
    }
    Ok(())
}
fn deduplicate_findings(
    findings: &mut Vec<ScannerFinding>,
    limits: &Limits,
) -> Result<(), &'static str> {
    let mut groups = BTreeMap::<(String, String, String), ScannerFinding>::new();
    for f in std::mem::take(findings) {
        let key = (f.rule_pack.clone(), f.namespace.clone(), f.rule.clone());
        if let Some(prior) = groups.get_mut(&key) {
            if prior.metadata != f.metadata
                || prior.scope != f.scope
                || prior.attack != f.attack
                || prior.mbc != f.mbc
            {
                return Err("conflicting duplicate finding");
            }
            prior.id = prior.id.clone().min(f.id);
            prior.locations.extend(f.locations);
            prior.locations.sort();
            prior.locations.dedup();
            prior.features.extend(f.features);
            prior.features.sort();
            prior.features.dedup();
            prior.evidence_ids.extend(f.evidence_ids);
            prior.evidence_ids.sort();
            prior.evidence_ids.dedup();
            if prior.locations.len() > limits.offsets || prior.features.len() > limits.features {
                return Err("deduplicated finding exceeds limit");
            }
        } else {
            groups.insert(key, f);
        }
    }
    *findings = groups.into_values().collect();
    Ok(())
}
