use std::env;
use std::fs;
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const LISTENER_ENV: &str = "RED_LAB_LISTENER";
pub const TOKEN_ENV: &str = "RED_LAB_TOKEN";
pub const HOST_CONFIG_FILE: &str = "host.toml";
pub const AGENT_CONFIG_FILE: &str = "agent.toml";

const PROTOCOL_PREFIX: &str = "RED-POWERSHELL-LAB/1";
const MIN_TOKEN_LENGTH: usize = 24;
const MAX_HANDSHAKE_LENGTH: usize = 512;
const FRAME_MAGIC: &[u8; 4] = b"RSL1";
const FRAME_HEADER_LENGTH: usize = 21;

pub const MAX_FRAME_PAYLOAD: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum FrameKind {
    Command = 1,
    Stdout = 2,
    Stderr = 3,
    Exit = 4,
    Close = 5,
    Error = 6,
}

impl TryFrom<u8> for FrameKind {
    type Error = io::Error;

    fn try_from(value: u8) -> Result<Self, io::Error> {
        match value {
            1 => Ok(Self::Command),
            2 => Ok(Self::Stdout),
            3 => Ok(Self::Stderr),
            4 => Ok(Self::Exit),
            5 => Ok(Self::Close),
            6 => Ok(Self::Error),
            _ => Err(invalid_input(format!(
                "알 수 없는 프레임 종류입니다: {value}"
            ))),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Frame {
    pub kind: FrameKind,
    pub request_id: u64,
    pub status: i32,
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LabConfig {
    pub version: u8,
    pub role: String,
    pub session_id: String,
    pub address: String,
    pub token: String,
}

impl LabConfig {
    pub fn validate(&self, expected_role: &str) -> io::Result<SocketAddr> {
        if self.version != 1 {
            return Err(invalid_input(format!(
                "지원하지 않는 설정 버전입니다: {}",
                self.version
            )));
        }
        if self.role != expected_role {
            return Err(invalid_input(format!(
                "설정 역할이 일치하지 않습니다: expected={expected_role}, actual={}",
                self.role
            )));
        }
        if self.session_id.trim().is_empty() {
            return Err(invalid_input("session_id가 비어 있습니다"));
        }
        validate_token(&self.token)?;
        parse_socket_address(&self.address)
    }
}

pub fn adjacent_config_path(file_name: &str) -> io::Result<PathBuf> {
    let executable = env::current_exe()?;
    let directory = executable
        .parent()
        .ok_or_else(|| io::Error::other("실행 파일 디렉터리를 찾지 못했습니다"))?;
    Ok(directory.join(file_name))
}

pub fn load_optional_adjacent_config(file_name: &str) -> io::Result<Option<LabConfig>> {
    let path = adjacent_config_path(file_name)?;
    if !path.exists() {
        return Ok(None);
    }
    load_config(&path).map(Some)
}

pub fn load_config(path: &Path) -> io::Result<LabConfig> {
    let text = fs::read_to_string(path)?;
    toml::from_str(&text).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("설정 파일을 읽지 못했습니다 ({}): {error}", path.display()),
        )
    })
}

pub fn write_config(path: &Path, config: &LabConfig) -> io::Result<()> {
    let text = toml::to_string_pretty(config).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("설정 파일 직렬화 실패: {error}"),
        )
    })?;
    fs::write(path, text)
}

impl Frame {
    pub fn new(kind: FrameKind, request_id: u64, status: i32, payload: Vec<u8>) -> Self {
        Self {
            kind,
            request_id,
            status,
            payload,
        }
    }
}

fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

pub fn session_token() -> io::Result<String> {
    let token = env::var(TOKEN_ENV)
        .map_err(|_| invalid_input(format!("{TOKEN_ENV} 환경 변수가 필요합니다")))?;

    validate_token(&token)?;
    Ok(token)
}

pub fn listener_address() -> io::Result<SocketAddr> {
    let configured = env::var(LISTENER_ENV)
        .map_err(|_| invalid_input(format!("{LISTENER_ENV} 환경 변수가 필요합니다")))?;
    parse_socket_address(&configured)
}

pub fn parse_socket_address(value: &str) -> io::Result<SocketAddr> {
    value.parse().map_err(|_| {
        invalid_input(format!(
            "{LISTENER_ENV}는 DNS 이름이 아닌 IP:PORT 형식이어야 합니다: {value}"
        ))
    })
}

fn validate_token(token: &str) -> io::Result<()> {
    if token.len() < MIN_TOKEN_LENGTH {
        return Err(invalid_input(format!(
            "{TOKEN_ENV}은 최소 {MIN_TOKEN_LENGTH}자여야 합니다"
        )));
    }

    if token.len() > 256 || token.contains(['\r', '\n']) {
        return Err(invalid_input(format!(
            "{TOKEN_ENV}은 256자 이하이고 줄바꿈을 포함하지 않아야 합니다"
        )));
    }

    Ok(())
}

pub async fn client_handshake<S>(stream: &mut S, token: &str) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    validate_token(token)?;
    let request = format!("{PROTOCOL_PREFIX} {token}\n");
    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;

    let response = read_line_limited(stream, 32).await?;
    if response != b"OK\n" {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "리스너가 세션을 승인하지 않았습니다",
        ));
    }

    Ok(())
}

pub async fn server_handshake<S>(stream: &mut S, expected_token: &str) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    validate_token(expected_token)?;
    let request = read_line_limited(stream, MAX_HANDSHAKE_LENGTH).await?;
    let expected = format!("{PROTOCOL_PREFIX} {expected_token}\n");

    if !constant_time_equal(&request, expected.as_bytes()) {
        stream.write_all(b"ERR\n").await?;
        stream.flush().await?;
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "세션 토큰 또는 프로토콜이 일치하지 않습니다",
        ));
    }

    stream.write_all(b"OK\n").await?;
    stream.flush().await?;
    Ok(())
}

pub async fn write_frame<W>(writer: &mut W, frame: &Frame) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    if frame.payload.len() > MAX_FRAME_PAYLOAD {
        return Err(invalid_input(format!(
            "프레임 payload가 최대 크기를 초과했습니다: {} > {MAX_FRAME_PAYLOAD}",
            frame.payload.len()
        )));
    }

    let payload_length = u32::try_from(frame.payload.len())
        .map_err(|_| invalid_input("프레임 payload 길이를 u32로 표현할 수 없습니다"))?;
    let mut header = [0_u8; FRAME_HEADER_LENGTH];
    header[0..4].copy_from_slice(FRAME_MAGIC);
    header[4] = frame.kind as u8;
    header[5..13].copy_from_slice(&frame.request_id.to_be_bytes());
    header[13..17].copy_from_slice(&frame.status.to_be_bytes());
    header[17..21].copy_from_slice(&payload_length.to_be_bytes());

    writer.write_all(&header).await?;
    writer.write_all(&frame.payload).await?;
    writer.flush().await
}

pub async fn read_frame<R>(reader: &mut R) -> io::Result<Frame>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0_u8; FRAME_HEADER_LENGTH];
    reader.read_exact(&mut header).await?;

    if &header[0..4] != FRAME_MAGIC {
        return Err(invalid_input("프레임 magic 값이 일치하지 않습니다"));
    }

    let kind = FrameKind::try_from(header[4])?;
    let request_id = u64::from_be_bytes(
        header[5..13]
            .try_into()
            .map_err(|_| invalid_input("request ID를 읽지 못했습니다"))?,
    );
    let status = i32::from_be_bytes(
        header[13..17]
            .try_into()
            .map_err(|_| invalid_input("status를 읽지 못했습니다"))?,
    );
    let payload_length = u32::from_be_bytes(
        header[17..21]
            .try_into()
            .map_err(|_| invalid_input("payload 길이를 읽지 못했습니다"))?,
    ) as usize;

    if payload_length > MAX_FRAME_PAYLOAD {
        return Err(invalid_input(format!(
            "수신 프레임 payload가 최대 크기를 초과했습니다: {payload_length} > {MAX_FRAME_PAYLOAD}"
        )));
    }

    let mut payload = vec![0_u8; payload_length];
    reader.read_exact(&mut payload).await?;

    Ok(Frame::new(kind, request_id, status, payload))
}

async fn read_line_limited<S>(stream: &mut S, limit: usize) -> io::Result<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    let mut line = Vec::with_capacity(limit.min(128));
    let mut byte = [0_u8; 1];

    while line.len() < limit {
        let bytes_read = stream.read(&mut byte).await?;
        if bytes_read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "핸드셰이크 도중 연결이 종료되었습니다",
            ));
        }

        line.push(byte[0]);
        if byte[0] == b'\n' {
            return Ok(line);
        }
    }

    Err(invalid_input("핸드셰이크가 허용 길이를 초과했습니다"))
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }

    left.iter()
        .zip(right.iter())
        .fold(0_u8, |difference, (a, b)| difference | (a ^ b))
        == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[test]
    fn permits_private_loopback_and_public_looking_addresses() {
        assert!(parse_socket_address("172.16.21.172:14444").is_ok());
        assert!(parse_socket_address("127.0.0.1:14444").is_ok());
        assert!(parse_socket_address("[fd00::1]:14444").is_ok());
        assert!(parse_socket_address("198.51.100.25:14444").is_ok());
    }

    #[test]
    fn rejects_dns_names_and_invalid_ports() {
        assert!(parse_socket_address("example.com:14444").is_err());
        assert!(parse_socket_address("172.16.21.172:70000").is_err());
    }

    #[test]
    fn compares_handshake_values_without_early_byte_exit() {
        assert!(constant_time_equal(b"same", b"same"));
        assert!(!constant_time_equal(b"same", b"sand"));
        assert!(!constant_time_equal(b"short", b"longer"));
    }

    #[tokio::test]
    async fn performs_matching_handshake() {
        let token = "matching-red-lab-token-2026";
        let (mut client, mut server) = duplex(1024);

        let (client_result, server_result) = tokio::join!(
            client_handshake(&mut client, token),
            server_handshake(&mut server, token)
        );

        assert!(client_result.is_ok());
        assert!(server_result.is_ok());
    }

    #[tokio::test]
    async fn rejects_mismatched_handshake() {
        let (mut client, mut server) = duplex(1024);

        let (client_result, server_result) = tokio::join!(
            client_handshake(&mut client, "client-red-lab-token-2026"),
            server_handshake(&mut server, "server-red-lab-token-2026")
        );

        assert_eq!(
            client_result
                .expect_err("client handshake should fail")
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            server_result
                .expect_err("server handshake should fail")
                .kind(),
            io::ErrorKind::PermissionDenied
        );
    }

    #[tokio::test]
    async fn round_trips_framed_message() {
        let expected = Frame::new(FrameKind::Stderr, 42, 7, b"sample output".to_vec());
        let (mut sender, mut receiver) = duplex(1024);

        let (write_result, read_result) = tokio::join!(
            write_frame(&mut sender, &expected),
            read_frame(&mut receiver)
        );

        write_result.expect("frame write should succeed");
        assert_eq!(read_result.expect("frame read should succeed"), expected);
    }

    #[test]
    fn validates_bundle_configuration_role_and_address() {
        let config = LabConfig {
            version: 1,
            role: "agent".to_string(),
            session_id: "test-session".to_string(),
            address: "198.51.100.25:14444".to_string(),
            token: "bundle-test-token-2026-abcdef".to_string(),
        };

        assert!(config.validate("agent").is_ok());
        assert!(config.validate("host").is_err());
    }
}
