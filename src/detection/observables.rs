//! Concrete observables only. Rule names, APIs and ATT&CK IDs never enter this extractor.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::net::IpAddr;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct Observable {
    pub kind: String,
    pub original: String,
    pub normalized: String,
    pub contextual: bool,
    pub confidence: u8,
    pub validation: String,
}
pub fn normalize(kind: &str, value: &str) -> Option<Observable> {
    if value.is_empty() || value.len() > 2048 || value.chars().any(char::is_control) {
        return None;
    }
    let raw = value.trim();
    if raw != value {
        return None;
    }
    let lower = raw.to_ascii_lowercase();
    let (normalized, contextual) = match kind {
        "ipv4" | "ipv6" | "ip" => {
            let ip: IpAddr = raw.parse().ok()?;
            if (kind == "ipv4" && !ip.is_ipv4()) || (kind == "ipv6" && !ip.is_ipv6()) {
                return None;
            }
            (ip.to_string(), contextual_ip(ip))
        }
        "domain" => {
            if !valid_domain(raw) {
                return None;
            }
            let d = lower.trim_end_matches('.').to_string();
            let c = contextual_domain(&d);
            (d, c)
        }
        "url" => {
            let url = reqwest::Url::parse(raw).ok()?;
            if !["http", "https", "ftp"].contains(&url.scheme())
                || !url.username().is_empty()
                || url.password().is_some()
            {
                return None;
            }
            // Query values and fragments frequently contain tokens/credentials. Do not export them.
            if url.query().is_some() || url.fragment().is_some() {
                return None;
            }
            let host = url.host_str()?.trim_matches(['[', ']']);
            let contextual = if let Ok(ip) = host.parse::<IpAddr>() {
                contextual_ip(ip)
            } else if valid_domain(host) {
                contextual_domain(host)
            } else {
                return None;
            };
            (url.to_string(), contextual)
        }
        "email" => {
            let (local, domain) = raw.rsplit_once('@')?;
            if local.is_empty()
                || local.len() > 64
                || local.starts_with('.')
                || local.ends_with('.')
                || local.contains("..")
                || !local
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b".!#$%&'*+-/=?^_`{|}~".contains(&b))
                || !valid_domain(domain)
            {
                return None;
            }
            (
                format!("{local}@{}", domain.to_ascii_lowercase()),
                contextual_domain(domain),
            )
        }
        "named_pipe" => {
            if !lower.starts_with("\\\\.\\pipe\\")
                || raw.len() <= 9
                || raw[9..].contains([':', '/', '\\'])
            {
                return None;
            }
            (lower, false)
        }
        "registry" => {
            let key = lower
                .replace("hkey_local_machine", "hklm")
                .replace("hkey_current_user", "hkcu")
                .replace("hkey_classes_root", "hkcr")
                .replace("hkey_users", "hku");
            if !["hklm\\", "hkcu\\", "hkcr\\", "hku\\"]
                .iter()
                .any(|p| key.starts_with(p))
                || key.len() > 1024
            {
                return None;
            }
            (key, false)
        }
        "file_path" => {
            let p = lower.replace('/', "\\");
            if raw.len() > 1024
                || !raw.as_bytes().first().is_some_and(u8::is_ascii_alphabetic)
                || raw.as_bytes().get(1) != Some(&b':')
                || !matches!(raw.as_bytes().get(2), Some(b'\\' | b'/'))
                || p[2..].contains([':', '*', '?', '"', '<', '>', '|'])
                || p.split('\\').any(|s| s == "..")
            {
                return None;
            }
            let contextual = p.starts_with("c:\\windows\\")
                || p.starts_with("c:\\program files\\")
                || p.ends_with("\\desktop.ini");
            (p, contextual)
        }
        "filename" => {
            if raw.len() > 255
                || raw.contains(['/', '\\', ':', '*', '?', '"', '<', '>', '|'])
                || !raw.contains('.')
            {
                return None;
            }
            let contextual = [
                "cmd.exe",
                "powershell.exe",
                "svchost.exe",
                "rundll32.exe",
                "explorer.exe",
                "ntdll.dll",
                "kernel32.dll",
            ]
            .contains(&lower.as_str());
            (lower, contextual)
        }
        "mutex" | "service" | "scheduled_task" => {
            // These types need typed telemetry or an explicit prefix; arbitrary strings are ambiguous.
            if raw.len() > 256 || raw.contains(['\0', '"', '<', '>', '|']) {
                return None;
            }
            (lower, false)
        }
        "user_agent" => {
            if raw.len() > 512 || !raw.contains('/') || !raw.is_ascii() {
                return None;
            }
            (raw.to_string(), raw.starts_with("Mozilla/"))
        }
        "certificate_sha256" => {
            if !super::validation::sha256(raw) {
                return None;
            }
            (lower, false)
        }
        "bitcoin_address" => {
            if !bitcoin_address(raw) {
                return None;
            }
            (raw.into(), false)
        }
        _ => return None,
    };
    Some(Observable {
        kind: if kind == "ip" {
            if normalized.contains(':') {
                "ipv6"
            } else {
                "ipv4"
            }
        } else {
            kind
        }
        .into(),
        original: raw.into(),
        normalized,
        contextual,
        confidence: 80,
        validation: "syntax_validated".into(),
    })
}
pub fn extract(value: &str) -> Vec<Observable> {
    if value.len() > 4096 {
        return vec![];
    }
    let mut result = BTreeSet::new();
    for token in std::iter::once(value).chain(value.split(|c: char| {
        c.is_ascii_whitespace() || matches!(c, '"' | '\'' | '<' | '>' | ',' | ';' | '(' | ')')
    })) {
        if token.is_empty() {
            continue;
        }
        for kind in [
            "ip",
            "url",
            "email",
            "named_pipe",
            "registry",
            "file_path",
            "bitcoin_address",
        ] {
            if let Some(o) = normalize(kind, token) {
                result.insert(o);
            }
        }
        if let Some((prefix, raw)) = token.split_once('=') {
            let kind = match prefix {
                "mutex" => "mutex",
                "service" => "service",
                "task" => "scheduled_task",
                "user-agent" => "user_agent",
                "cert-sha256" => "certificate_sha256",
                _ => continue,
            };
            if let Some(o) = normalize(kind, raw) {
                result.insert(o);
            }
        } else if let Some(o) = normalize("domain", token) {
            result.insert(o);
        }
    }
    result.into_iter().collect()
}
pub fn valid_domain(raw: &str) -> bool {
    let raw = raw.strip_suffix('.').unwrap_or(raw);
    if raw.len() > 253 || !raw.contains('.') || raw.parse::<IpAddr>().is_ok() {
        return false;
    }
    let labels = raw.split('.').collect::<Vec<_>>();
    let Some(tld) = labels.last() else {
        return false;
    };
    tld.len() >= 2
        && tld.bytes().all(|b| b.is_ascii_alphabetic())
        && ![
            "exe", "dll", "sys", "bat", "cmd", "ps1", "txt", "pdb", "json", "xml", "dat", "ini",
            "log",
        ]
        .contains(&tld.to_ascii_lowercase().as_str())
        && labels.iter().all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}
pub fn contextual_domain(raw: &str) -> bool {
    let d = raw.trim_end_matches('.').to_ascii_lowercase();
    [
        "example.com",
        "example.net",
        "example.org",
        "localhost",
        "local",
        "test",
        "invalid",
        "example",
        "windows.com",
        "microsoft.com",
    ]
    .iter()
    .any(|v| d == *v || d.ends_with(&format!(".{v}")))
}
pub fn contextual_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            let [a, b, c, _] = v.octets();
            v.is_private()
                || v.is_loopback()
                || v.is_link_local()
                || v.is_broadcast()
                || v.is_unspecified()
                || v.is_multicast()
                || a == 0
                || a >= 240
                || (a == 100 && (64..=127).contains(&b))
                || (a == 192 && b == 0)
                || (a == 192 && b == 0 && c == 2)
                || (a == 198 && (b == 18 || b == 19 || (b == 51 && c == 100)))
                || (a == 203 && b == 0 && c == 113)
        }
        IpAddr::V6(v) => v
            .to_ipv4_mapped()
            .map(|v| contextual_ip(IpAddr::V4(v)))
            .unwrap_or_else(|| {
                let s = v.segments();
                v.is_loopback()
                    || v.is_unspecified()
                    || v.is_multicast()
                    || s[0] & 0xfe00 == 0xfc00
                    || s[0] & 0xffc0 == 0xfe80
                    || (s[0] == 0x2001 && (s[1] == 0x0db8 || s[1] < 0x200))
                    || s[0] & 0xe000 != 0x2000
            }),
    }
}
fn bitcoin_address(value: &str) -> bool {
    if !(26..=35).contains(&value.len()) {
        return false;
    }
    let alphabet = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let mut decoded = vec![0u8];
    for b in value.bytes() {
        let Some(index) = alphabet.iter().position(|c| *c == b) else {
            return false;
        };
        let mut carry = index as u32;
        for byte in decoded.iter_mut().rev() {
            carry += u32::from(*byte) * 58;
            *byte = carry as u8;
            carry >>= 8;
        }
        while carry > 0 {
            decoded.insert(0, carry as u8);
            carry >>= 8;
        }
    }
    for _ in value.bytes().take_while(|b| *b == b'1') {
        decoded.insert(0, 0);
    }
    decoded.len() == 25
        && [0, 5].contains(&decoded[0])
        && Sha256::digest(Sha256::digest(&decoded[..21]))[..4] == decoded[21..]
}
