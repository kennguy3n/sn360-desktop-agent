//! Connection management for Wazuh server communication.
//!
//! Handles TCP/UDP transport, automatic reconnection with exponential
//! backoff, keepalive messages, and message batching.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tracing::{debug, info, warn};

use crate::crypto::{CryptoError, WazuhCipher};
use crate::protocol::WazuhMessage;

/// Strip the cleartext routing prefix `!{agent_id}!{crypto_token}` that
/// Wazuh's `remoted` prepends to every frame it sends to an agent
/// (mirrors what agents themselves send via `build_wire_frame`). The
/// crypto_token is `:` for Blowfish and `#AES:` for AES; the body that
/// follows is the encrypted ciphertext that the cipher knows how to
/// decode. Without stripping this 6-12 byte cleartext header, the
/// ciphertext length is no longer a multiple of the cipher's block
/// size and CBC decryption silently returns an empty buffer, which
/// previously surfaced as a stream of `received empty server frame`
/// debug logs and made every server-pushed Active-Response command a
/// no-op.
fn strip_routing_prefix(buf: &[u8]) -> &[u8] {
    // Frames from `remoted` to the agent omit the `!{agent_id}!` prefix
    // that the agent itself sends -- the agent already knows its own id
    // so the cleartext routing header is just the crypto token.
    let body = if buf.first() == Some(&b'!') {
        match buf[1..].iter().position(|&b| b == b'!') {
            Some(idx) => &buf[idx + 2..],
            None => buf,
        }
    } else {
        buf
    };
    if body.starts_with(b"#AES:") {
        &body[5..]
    } else if body.first() == Some(&b':') {
        &body[1..]
    } else {
        body
    }
}

/// Decrypt a received frame, translating an empty decrypted payload
/// into `Ok(None)` so the caller can distinguish a legitimate
/// keep-open frame from a real decryption failure.
fn decrypt_frame(
    cipher: Option<&WazuhCipher>,
    buf: Vec<u8>,
) -> Result<Option<Vec<u8>>, ConnectionError> {
    match cipher {
        Some(cipher) => {
            let body = strip_routing_prefix(&buf);
            debug!(
                buf_len = buf.len(),
                body_len = body.len(),
                first_buf_byte = format!("{:#04x}", buf.first().copied().unwrap_or(0)),
                first_body_byte = format!("{:#04x}", body.first().copied().unwrap_or(0)),
                "decrypt_frame"
            );
            match cipher.decrypt(body) {
                Ok(plaintext) => {
                    debug!(
                        plaintext_len = plaintext.len(),
                        first_byte = format!("{:#04x}", plaintext.first().copied().unwrap_or(0)),
                        "decrypted server frame"
                    );
                    Ok(Some(plaintext))
                }
                Err(CryptoError::EmptyPayload) => Ok(None),
                Err(e) => Err(ConnectionError::ReceiveFailed(e.to_string())),
            }
        }
        None => {
            if buf.is_empty() {
                Ok(None)
            } else {
                Ok(Some(buf))
            }
        }
    }
}

/// Format a host and port into a socket address string.
///
/// IPv6 addresses are wrapped in brackets so that the result is a valid
/// socket address (e.g. `[::1]:1514`).  IPv4 addresses and hostnames are
/// returned as-is (`10.0.0.1:1514`).
pub fn format_socket_addr(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{}]:{}", host, port)
    } else {
        format!("{}:{}", host, port)
    }
}

/// Connection errors.
#[derive(Debug, thiserror::Error)]
pub enum ConnectionError {
    #[error("connection failed: {0}")]
    ConnectFailed(String),
    #[error("send failed: {0}")]
    SendFailed(String),
    #[error("receive failed: {0}")]
    ReceiveFailed(String),
    #[error("connection closed by server")]
    Closed,
    #[error("authentication failed")]
    AuthFailed,
    #[error("timeout")]
    Timeout,
}

/// Connection configuration.
#[derive(Debug, Clone)]
pub struct ConnectionConfig {
    /// Server address (host:port).
    pub server_address: String,
    /// Server port.
    pub server_port: u16,
    /// Transport protocol.
    pub protocol: TransportProtocol,
    /// Initial reconnection delay.
    pub reconnect_initial: Duration,
    /// Maximum reconnection delay.
    pub reconnect_max: Duration,
    /// Reconnection backoff multiplier.
    pub reconnect_multiplier: f64,
    /// Keepalive interval.
    pub keepalive_interval: Duration,
    /// Message batch window.
    pub batch_window: Duration,
    /// Maximum messages per batch.
    pub max_batch_size: usize,
}

/// Transport protocol selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportProtocol {
    Tcp,
    Udp,
}

impl Default for ConnectionConfig {
    fn default() -> Self {
        Self {
            server_address: "localhost".to_string(),
            server_port: 1514,
            protocol: TransportProtocol::Tcp,
            reconnect_initial: Duration::from_secs(1),
            reconnect_max: Duration::from_secs(60),
            reconnect_multiplier: 2.0,
            keepalive_interval: Duration::from_secs(600),
            batch_window: Duration::from_secs(5),
            max_batch_size: 100,
        }
    }
}

/// Manages the connection to the Wazuh server.
///
/// Handles reconnection, message encryption, and transport.
pub struct ConnectionManager {
    config: ConnectionConfig,
    cipher: Option<WazuhCipher>,
    stream: Option<TcpStream>,
    udp_socket: Option<UdpSocket>,
    connected: bool,
    consecutive_failures: u32,
}

impl ConnectionManager {
    /// Create a new connection manager.
    pub fn new(config: ConnectionConfig) -> Self {
        Self {
            config,
            cipher: None,
            stream: None,
            udp_socket: None,
            connected: false,
            consecutive_failures: 0,
        }
    }

    /// Set the encryption cipher (after enrollment).
    pub fn set_cipher(&mut self, cipher: WazuhCipher) {
        self.cipher = Some(cipher);
    }

    /// Check if currently connected.
    pub fn is_connected(&self) -> bool {
        self.connected
    }

    /// Connect to the Wazuh server.
    pub async fn connect(&mut self) -> Result<(), ConnectionError> {
        let addr = format_socket_addr(&self.config.server_address, self.config.server_port);
        info!(address = %addr, "connecting to server");

        match &self.config.protocol {
            TransportProtocol::Tcp => {
                let timeout = Duration::from_secs(10);
                let stream = tokio::time::timeout(timeout, TcpStream::connect(&addr))
                    .await
                    .map_err(|_| ConnectionError::Timeout)?
                    .map_err(|e| ConnectionError::ConnectFailed(e.to_string()))?;

                // Set TCP keepalive
                let sock_ref = socket2::SockRef::from(&stream);
                let keepalive = socket2::TcpKeepalive::new().with_time(Duration::from_secs(60));
                let _ = sock_ref.set_tcp_keepalive(&keepalive);

                self.stream = Some(stream);
                self.connected = true;
                self.consecutive_failures = 0;
                info!(address = %addr, "connected to server");
                Ok(())
            }
            TransportProtocol::Udp => {
                let bind_addr = if self.config.server_address.contains(':') {
                    "[::]:0"
                } else {
                    "0.0.0.0:0"
                };
                let socket = UdpSocket::bind(bind_addr)
                    .await
                    .map_err(|e| ConnectionError::ConnectFailed(e.to_string()))?;
                socket
                    .connect(&addr)
                    .await
                    .map_err(|e| ConnectionError::ConnectFailed(e.to_string()))?;
                self.udp_socket = Some(socket);
                self.connected = true;
                self.consecutive_failures = 0;
                info!(address = %addr, "connected UDP socket to server");
                Ok(())
            }
        }
    }

    /// Connect with automatic retry and exponential backoff.
    pub async fn connect_with_retry(&mut self) -> Result<(), ConnectionError> {
        let mut delay = self.config.reconnect_initial;

        loop {
            match self.connect().await {
                Ok(()) => return Ok(()),
                Err(e) => {
                    self.consecutive_failures += 1;
                    warn!(
                        error = %e,
                        attempt = self.consecutive_failures,
                        next_retry_secs = delay.as_secs(),
                        "connection failed, retrying"
                    );

                    tokio::time::sleep(delay).await;

                    // Exponential backoff with cap
                    delay = Duration::from_secs_f64(
                        (delay.as_secs_f64() * self.config.reconnect_multiplier)
                            .min(self.config.reconnect_max.as_secs_f64()),
                    );
                }
            }
        }
    }

    /// Send a message to the server.
    ///
    /// The message body is encrypted and prefixed with the agent ID
    /// (in the clear) so the server can look up the correct key.
    /// Wire format: `4-byte-length | "!{agent_id}!{crypto_token}" | encrypted_body`
    ///
    /// On transient failures (broken pipe, connection reset) the method
    /// reconnects once and retries the send.
    pub async fn send(&mut self, message: &WazuhMessage) -> Result<(), ConnectionError> {
        let data = self.build_wire_frame(message)?;

        match self.send_raw(&data).await {
            Ok(()) => Ok(()),
            Err(e) => {
                warn!(error = %e, "send failed, reconnecting");
                // Reconnect and retry once.
                self.disconnect().await;
                self.connect_with_retry().await?;
                // Re-encrypt with fresh frame (counters already advanced, but
                // the server is tolerant of counter gaps).
                let data2 = self.build_wire_frame(message)?;
                self.send_raw(&data2).await
            }
        }
    }

    /// Build the encrypted wire frame for a message.
    fn build_wire_frame(&self, message: &WazuhMessage) -> Result<Vec<u8>, ConnectionError> {
        let body = message.encode_body();

        debug!(
            agent_id = %message.agent_id,
            msg_type = ?message.msg_type,
            body_len = body.len(),
            body_preview = %String::from_utf8_lossy(&body[..body.len().min(120)]),
            "raw plaintext before encryption"
        );

        let data = if let Some(cipher) = &self.cipher {
            let encrypted = cipher
                .encrypt(&body)
                .map_err(|e| ConnectionError::SendFailed(e.to_string()))?;

            debug!(encrypted_len = encrypted.len(), "encrypted payload");

            // Wire format: !{agent_id}!{crypto_token}{encrypted_payload}
            // crypto_token is ":" for Blowfish, "#AES:" for AES
            let mut wire = format!("!{}!{}", message.agent_id, cipher.crypto_token()).into_bytes();
            wire.extend_from_slice(&encrypted);
            wire
        } else {
            // No cipher — fall back to legacy full-message encoding.
            message.encode()
        };

        Ok(data)
    }

    /// Send raw bytes over the transport.
    async fn send_raw(&mut self, data: &[u8]) -> Result<(), ConnectionError> {
        match &self.config.protocol {
            TransportProtocol::Tcp => {
                let stream = self.stream.as_mut().ok_or(ConnectionError::Closed)?;

                // Wazuh TCP protocol: 4-byte length prefix (little-endian / native on x86_64) + data
                // Wazuh's wnet_order() is a no-op on little-endian, so the header is native byte order.
                let len = (data.len() as u32).to_le_bytes();
                stream
                    .write_all(&len)
                    .await
                    .map_err(|e| ConnectionError::SendFailed(e.to_string()))?;
                stream
                    .write_all(data)
                    .await
                    .map_err(|e| ConnectionError::SendFailed(e.to_string()))?;
                stream
                    .flush()
                    .await
                    .map_err(|e| ConnectionError::SendFailed(e.to_string()))?;

                debug!(bytes = data.len(), "sent message");
                Ok(())
            }
            TransportProtocol::Udp => {
                let socket = self.udp_socket.as_ref().ok_or(ConnectionError::Closed)?;
                socket
                    .send(data)
                    .await
                    .map_err(|e| ConnectionError::SendFailed(e.to_string()))?;
                debug!(bytes = data.len(), "sent UDP message");
                Ok(())
            }
        }
    }

    /// Receive a message from the server.
    ///
    /// Returns `Ok(Some(bytes))` when a real payload was received,
    /// `Ok(None)` when the peer sent a legitimate keep-open frame that
    /// decrypted to an empty body (so callers can distinguish "no data"
    /// from a real decryption failure), and `Err(_)` on transport or
    /// decryption errors.
    pub async fn receive(&mut self) -> Result<Option<Vec<u8>>, ConnectionError> {
        match &self.config.protocol {
            TransportProtocol::Tcp => {
                let stream = self.stream.as_mut().ok_or(ConnectionError::Closed)?;

                // Read 4-byte length prefix
                let mut len_buf = [0u8; 4];
                stream
                    .read_exact(&mut len_buf)
                    .await
                    .map_err(|e| ConnectionError::ReceiveFailed(e.to_string()))?;
                let len = u32::from_le_bytes(len_buf) as usize;

                // Sanity check on message size (max 64 KB)
                if len > 65536 {
                    return Err(ConnectionError::ReceiveFailed(format!(
                        "message too large: {} bytes",
                        len
                    )));
                }

                // Read the message body
                let mut buf = vec![0u8; len];
                stream
                    .read_exact(&mut buf)
                    .await
                    .map_err(|e| ConnectionError::ReceiveFailed(e.to_string()))?;

                decrypt_frame(self.cipher.as_ref(), buf)
            }
            TransportProtocol::Udp => {
                let socket = self.udp_socket.as_ref().ok_or(ConnectionError::Closed)?;
                let mut buf = vec![0u8; 65536];
                let n = socket
                    .recv(&mut buf)
                    .await
                    .map_err(|e| ConnectionError::ReceiveFailed(e.to_string()))?;
                buf.truncate(n);

                decrypt_frame(self.cipher.as_ref(), buf)
            }
        }
    }

    /// Disconnect from the server.
    pub async fn disconnect(&mut self) {
        if let Some(stream) = self.stream.take() {
            let _ = stream.into_std();
        }
        self.udp_socket.take();
        self.connected = false;
        info!("disconnected from server");
    }
}
