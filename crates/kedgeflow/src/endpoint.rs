//! Pins trusted HTTP endpoint authority/path before authentication and authority
//! use. This is not caller authentication or workstation containment.
use crate::error::{Error, Result};
use axum::http::{HeaderMap, StatusCode, Uri};
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Clone, Debug)]
pub struct EndpointPolicy {
    authority: String,
    path: String,
}

impl EndpointPolicy {
    /// Preserve the raw configured URL for DPoP elsewhere; URL parsers can
    /// normalize forbidden dot segments or legacy numeric host aliases.
    pub fn new(external_url: &str) -> Result<Self> {
        let rest = external_url
            .strip_prefix("https://")
            .ok_or_else(|| invalid("external_url requires HTTPS"))?;
        let (authority, tail) = rest
            .split_once('/')
            .ok_or_else(|| invalid("external_url requires an explicit absolute path"))?;
        let path = format!("/{tail}");
        if path.contains(['?', '#', '%', '\\'])
            || !path.is_ascii()
            || !path
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"/-._~!$&\'()*+,;=:@".contains(&c))
            || path.contains("//")
            || path.split('/').any(|s| s == "." || s == "..")
        {
            return Err(invalid(
                "external_url requires an unescaped unambiguous path",
            ));
        }
        let authority = endpoint_authority(authority)?;
        // The actual HTTP client uses URL semantics. Refuse inputs that its
        // normalizer interprets as another authority (e.g. hexadecimal IPv4).
        let parsed =
            url::Url::parse(external_url).map_err(|_| invalid("invalid HTTPS endpoint URL"))?;
        let mut parsed_authority = match parsed.host() {
            Some(url::Host::Domain(host)) => host.to_ascii_lowercase(),
            Some(url::Host::Ipv4(address)) => address.to_string(),
            Some(url::Host::Ipv6(address)) => format!("[{address}]"),
            None => return Err(invalid("missing HTTPS endpoint authority")),
        };
        if let Some(port) = parsed.port()
            && port != 443
        {
            parsed_authority.push_str(&format!(":{port}"));
        }
        if parsed_authority != authority || parsed.path() != path {
            return Err(invalid(
                "HTTPS endpoint normalizes to a different authority or path",
            ));
        }
        Ok(Self { authority, path })
    }

    pub fn authority(&self) -> &str {
        &self.authority
    }
    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn validate(&self, headers: &HeaderMap, uri: &Uri) -> Result<()> {
        if let Some(status) = self.rejection_status(headers, uri) {
            return Err(Error::Refused(format!(
                "endpoint boundary refusal ({})",
                status.as_u16()
            )));
        }
        Ok(())
    }

    /// HTTP status remains distinct from the cryptographic gateway error, and
    /// callers should attach Cache-Control: no-store to refusals.
    pub fn rejection_status(&self, headers: &HeaderMap, uri: &Uri) -> Option<StatusCode> {
        if headers.contains_key("origin") {
            return Some(StatusCode::FORBIDDEN);
        }
        let mut hosts = headers.get_all("host").iter();
        let Some(host) = hosts.next() else {
            return Some(StatusCode::MISDIRECTED_REQUEST);
        };
        if hosts.next().is_some() {
            return Some(StatusCode::MISDIRECTED_REQUEST);
        }
        let Ok(host) = host.to_str() else {
            return Some(StatusCode::MISDIRECTED_REQUEST);
        };
        match endpoint_authority(host) {
            Ok(actual) if actual == self.authority => (),
            _ => return Some(StatusCode::MISDIRECTED_REQUEST),
        }
        if uri.scheme().is_some() || uri.authority().is_some() || uri.query().is_some() {
            return Some(StatusCode::BAD_REQUEST);
        }
        if uri.path() != self.path {
            return Some(StatusCode::NOT_FOUND);
        }
        None
    }
}

pub fn endpoint_authority(authority: &str) -> Result<String> {
    if authority.is_empty()
        || authority.len() > 300
        || authority.contains([' ', '\t', '\r', '\n', ',', '/', '@', '\\', '?', '#', '%'])
        || authority.ends_with(':')
    {
        return Err(invalid("invalid endpoint authority"));
    }
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let (address, suffix) = rest
            .split_once(']')
            .ok_or_else(|| invalid("invalid IPv6 authority"))?;
        let address = address
            .parse::<Ipv6Addr>()
            .map_err(|_| invalid("invalid IPv6 authority"))?;
        let port = if suffix.is_empty() {
            None
        } else {
            Some(
                suffix
                    .strip_prefix(':')
                    .ok_or_else(|| invalid("invalid IPv6 port"))?,
            )
        };
        (format!("[{address}]"), port)
    } else {
        let mut pieces = authority.split(':');
        let raw_host = pieces.next().unwrap_or_default();
        let port = pieces.next();
        if pieces.next().is_some() || raw_host.is_empty() || raw_host.contains(['[', ']']) {
            return Err(invalid("invalid hostname authority"));
        }
        let host = if let Ok(ipv4) = raw_host.parse::<Ipv4Addr>() {
            ipv4.to_string()
        } else {
            if raw_host.len() > 253
                || raw_host.ends_with('.')
                || raw_host.bytes().all(|c| c.is_ascii_digit() || c == b'.')
                || raw_host.split('.').any(|label| {
                    label.is_empty()
                        || label.len() > 63
                        || label.starts_with('-')
                        || label.ends_with('-')
                        || !label
                            .bytes()
                            .all(|c| c.is_ascii_alphanumeric() || c == b'-')
                })
            {
                return Err(invalid("invalid ASCII hostname"));
            }
            raw_host.to_ascii_lowercase()
        };
        (host, port)
    };
    match port {
        None => Ok(host),
        Some(port) => {
            if port.is_empty() || port.starts_with('0') || !port.bytes().all(|c| c.is_ascii_digit())
            {
                return Err(invalid("invalid endpoint port"));
            }
            let port = port
                .parse::<u16>()
                .map_err(|_| invalid("invalid endpoint port"))?;
            if port == 0 {
                return Err(invalid("invalid endpoint port"));
            }
            if port == 443 {
                Ok(host)
            } else {
                Ok(format!("{host}:{port}"))
            }
        }
    }
}
fn invalid(s: &str) -> Error {
    Error::Invalid(s.to_owned())
}
