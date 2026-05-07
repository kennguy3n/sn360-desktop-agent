//! Agent enrollment with the Wazuh server.
//!
//! Implements the authd enrollment protocol on port 1515.
//! Supports both pre-shared key and password-based enrollment.
//! Uses TLS for the enrollment connection (Wazuh authd requires SSL).

use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error as RustlsError, SignatureScheme};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tracing::info;

/// Enrollment errors.
#[derive(Debug, thiserror::Error)]
pub enum EnrollmentError {
    #[error("enrollment connection failed: {0}")]
    ConnectionFailed(String),
    #[error("enrollment rejected by server: {0}")]
    Rejected(String),
    #[error("invalid server response: {0}")]
    InvalidResponse(String),
    #[error("key storage failed: {0}")]
    StorageFailed(String),
    #[error("timeout during enrollment")]
    Timeout,
}

/// Agent key information stored after enrollment.
#[derive(Debug, Clone)]
pub struct AgentKey {
    /// Assigned agent ID.
    pub id: String,
    /// Agent name.
    pub name: String,
    /// Server-assigned IP or "any".
    pub ip: String,
    /// Pre-shared key for encryption.
    pub key: String,
}

impl AgentKey {
    /// Encode the key in Wazuh client.keys format.
    pub fn to_keys_line(&self) -> String {
        format!("{} {} {} {}", self.id, self.name, self.ip, self.key)
    }

    /// Parse a key from Wazuh client.keys format.
    pub fn from_keys_line(line: &str) -> Option<Self> {
        let parts: Vec<&str> = line.splitn(4, ' ').collect();
        if parts.len() == 4 {
            Some(Self {
                id: parts[0].to_string(),
                name: parts[1].to_string(),
                ip: parts[2].to_string(),
                key: parts[3].to_string(),
            })
        } else {
            None
        }
    }
}

/// Enrollment client for registering with a Wazuh server.
pub struct EnrollmentClient {
    /// Enrollment server address.
    server: String,
    /// Enrollment server port.
    port: u16,
    /// Agent name to register.
    agent_name: String,
    /// Optional enrollment password/key.
    password: Option<String>,
    /// Optional group assignment.
    groups: Option<Vec<String>>,
}

impl EnrollmentClient {
    /// Create a new enrollment client.
    pub fn new(server: &str, port: u16, agent_name: &str) -> Self {
        Self {
            server: server.to_string(),
            port,
            agent_name: agent_name.to_string(),
            password: None,
            groups: None,
        }
    }

    /// Set the enrollment password.
    pub fn with_password(mut self, password: &str) -> Self {
        self.password = Some(password.to_string());
        self
    }

    /// Set group assignments.
    pub fn with_groups(mut self, groups: Vec<String>) -> Self {
        self.groups = Some(groups);
        self
    }

    /// Perform enrollment and return the assigned agent key.
    ///
    /// Connects to the Wazuh authd service over TLS (port 1515).
    /// Accepts self-signed certificates since Wazuh uses its own CA.
    pub async fn enroll(&self) -> Result<AgentKey, EnrollmentError> {
        let addr = crate::connection::format_socket_addr(&self.server, self.port);
        info!(address = %addr, agent = %self.agent_name, "starting enrollment");

        // Connect to enrollment server over TLS
        let timeout = std::time::Duration::from_secs(30);
        let tcp_stream = tokio::time::timeout(timeout, TcpStream::connect(&addr))
            .await
            .map_err(|_| EnrollmentError::Timeout)?
            .map_err(|e| EnrollmentError::ConnectionFailed(e.to_string()))?;

        // Configure TLS (accept self-signed certs from Wazuh authd)
        let tls_config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyCert))
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(tls_config));
        let server_name: ServerName<'static> =
            if let Ok(ip) = self.server.parse::<std::net::IpAddr>() {
                ServerName::IpAddress(ip.into())
            } else {
                ServerName::try_from(self.server.clone()).map_err(|e| {
                    EnrollmentError::ConnectionFailed(format!("invalid server name: {e}"))
                })?
            };

        let tls_stream = tokio::time::timeout(timeout, connector.connect(server_name, tcp_stream))
            .await
            .map_err(|_| EnrollmentError::Timeout)?
            .map_err(|e| EnrollmentError::ConnectionFailed(format!("TLS handshake failed: {e}")))?;

        let (reader, mut writer) = tokio::io::split(tls_stream);
        let mut reader = BufReader::new(reader);

        // Build enrollment request
        // Format: OSSEC A:'agent_name'\n
        // With password: OSSEC PASS: password OSSEC A:'agent_name'\n
        let request = if let Some(ref password) = self.password {
            format!("OSSEC PASS: {} OSSEC A:'{}'\n", password, self.agent_name)
        } else {
            format!("OSSEC A:'{}'\n", self.agent_name)
        };

        // Send enrollment request
        writer
            .write_all(request.as_bytes())
            .await
            .map_err(|e| EnrollmentError::ConnectionFailed(e.to_string()))?;
        writer
            .flush()
            .await
            .map_err(|e| EnrollmentError::ConnectionFailed(e.to_string()))?;

        // Read response (with timeout)
        // Wazuh authd may close the connection without TLS close_notify,
        // so we tolerate the missing close_notify when we already have data.
        let mut response = String::new();
        match tokio::time::timeout(timeout, reader.read_line(&mut response)).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => {
                // If we already got data, the EOF error is expected from Wazuh authd
                if response.is_empty() {
                    return Err(EnrollmentError::InvalidResponse(e.to_string()));
                }
                // Otherwise we have the response, just the connection closed abruptly
            }
            Err(_) => return Err(EnrollmentError::Timeout),
        }

        let response = response.trim();
        info!(response = %response, "enrollment response received");

        // Parse response
        // Success format: OSSEC K:'<id> <name> <ip> <key>'
        if let Some(key_data) = response.strip_prefix("OSSEC K:'") {
            let key_data = key_data.trim_end_matches('\'');
            let agent_key = AgentKey::from_keys_line(key_data).ok_or_else(|| {
                EnrollmentError::InvalidResponse("failed to parse agent key".to_string())
            })?;

            info!(
                agent_id = %agent_key.id,
                agent_name = %agent_key.name,
                "enrollment successful"
            );

            Ok(agent_key)
        } else if response.starts_with("ERROR") {
            Err(EnrollmentError::Rejected(response.to_string()))
        } else {
            Err(EnrollmentError::InvalidResponse(response.to_string()))
        }
    }
}

/// A TLS certificate verifier that accepts any certificate.
///
/// Wazuh authd uses self-signed certificates, so we need to skip
/// certificate verification during enrollment. The enrollment
/// protocol itself uses a password for authentication.
#[derive(Debug)]
struct AcceptAnyCert;

impl ServerCertVerifier for AcceptAnyCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
        ]
    }
}

/// Path to the agent keys file.
///
/// When `override_path` is `Some`, that path is used verbatim. Otherwise the
/// platform default applies.
pub fn keys_file_path(override_path: Option<&Path>) -> PathBuf {
    if let Some(p) = override_path {
        return p.to_path_buf();
    }
    #[cfg(unix)]
    {
        PathBuf::from("/etc/sn360-desktop-agent/client.keys")
    }
    #[cfg(windows)]
    {
        PathBuf::from(r"C:\Program Files\SN360DesktopAgent\client.keys")
    }
}

/// Load an existing agent key from disk.
pub fn load_agent_key(override_path: Option<&Path>) -> Option<AgentKey> {
    let path = keys_file_path(override_path);
    let contents = std::fs::read_to_string(&path).ok()?;
    let line = contents.lines().next()?;
    AgentKey::from_keys_line(line.trim())
}

/// Save an agent key to disk.
pub fn save_agent_key(key: &AgentKey, override_path: Option<&Path>) -> Result<(), EnrollmentError> {
    let path = keys_file_path(override_path);

    // Ensure parent directory exists
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| EnrollmentError::StorageFailed(e.to_string()))?;
    }

    std::fs::write(&path, key.to_keys_line())
        .map_err(|e| EnrollmentError::StorageFailed(e.to_string()))?;

    // Set restrictive permissions on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o640);
        std::fs::set_permissions(&path, perms)
            .map_err(|e| EnrollmentError::StorageFailed(e.to_string()))?;
    }

    info!(path = %path.display(), "agent key saved");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_agent_key_roundtrip() {
        let key = AgentKey {
            id: "001".to_string(),
            name: "test-agent".to_string(),
            ip: "any".to_string(),
            key: "abc123def456".to_string(),
        };

        let line = key.to_keys_line();
        assert_eq!(line, "001 test-agent any abc123def456");

        let parsed = AgentKey::from_keys_line(&line).unwrap();
        assert_eq!(parsed.id, "001");
        assert_eq!(parsed.name, "test-agent");
        assert_eq!(parsed.ip, "any");
        assert_eq!(parsed.key, "abc123def456");
    }

    #[test]
    fn test_agent_key_parse_invalid() {
        assert!(AgentKey::from_keys_line("too short").is_none());
        assert!(AgentKey::from_keys_line("only two parts").is_none());
    }
}
