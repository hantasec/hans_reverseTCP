use std::collections::HashMap;
use std::io;
use std::io::BufRead as _;
use std::io::Write as _;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use encoding_rs::EUC_KR;
use powershell_reverse_lab::{
    Frame, FrameKind, HOST_CONFIG_FILE, load_optional_adjacent_config, parse_socket_address,
    read_frame, server_handshake, session_token, write_frame,
};
use tokio::fs::{self, File, OpenOptions};
use tokio::io::AsyncWriteExt;
use tokio::net::tcp::OwnedReadHalf;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio::time::timeout;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

fn prompt(label: &str) -> io::Result<String> {
    print!("{label}");
    io::stdout().flush()?;

    let mut value = String::new();
    if io::stdin().read_line(&mut value)? == 0 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "입력 스트림이 종료되었습니다",
        ));
    }
    Ok(value.trim().to_string())
}

fn parse_bind_address(ip_text: &str, port_text: &str) -> io::Result<SocketAddr> {
    let ip: IpAddr = ip_text.parse().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("올바르지 않은 IP 주소입니다: {ip_text}"),
        )
    })?;
    let port: u16 = port_text.parse().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("포트는 1~65535 범위의 숫자여야 합니다: {port_text}"),
        )
    })?;
    if port == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "포트 0은 사용할 수 없습니다",
        ));
    }

    parse_socket_address(&SocketAddr::new(ip, port).to_string())
}

fn prompt_bind_address() -> io::Result<SocketAddr> {
    loop {
        let ip = prompt("리스너 바인드 IP: ")?;
        let port = prompt("리스너 포트: ")?;
        match parse_bind_address(&ip, &port) {
            Ok(address) => return Ok(address),
            Err(error) => eprintln!("[RED-LAB] 입력 오류: {error}. 다시 입력하세요."),
        }
    }
}

fn runtime_settings() -> io::Result<(SocketAddr, String, Option<String>)> {
    if let Some(config) = load_optional_adjacent_config(HOST_CONFIG_FILE)? {
        let address = config.validate("host")?;
        return Ok((address, config.token, Some(config.session_id)));
    }

    Ok((prompt_bind_address()?, session_token()?, None))
}

enum ConsoleInput {
    Line(String),
    Closed,
    Error(String),
}

enum NetworkEvent {
    Frame(Frame),
    Closed,
    Error(String),
}

enum PendingRequest {
    User {
        stdout: TextBuffer,
        stderr: TextBuffer,
        saw_output: bool,
        ended_with_newline: bool,
    },
    Prompt {
        output: Vec<u8>,
    },
}

#[derive(Default)]
struct TextBuffer {
    pending: Vec<u8>,
}

impl TextBuffer {
    fn push(&mut self, bytes: &[u8]) -> String {
        self.pending.extend_from_slice(bytes);
        let Some(last_newline) = self.pending.iter().rposition(|byte| *byte == b'\n') else {
            return String::new();
        };

        let complete = self.pending.drain(..=last_newline).collect::<Vec<_>>();
        decode_remote_text(&complete)
    }

    fn finish(&mut self) -> String {
        decode_remote_text(&std::mem::take(&mut self.pending))
    }
}

fn unix_timestamp_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

async fn create_audit_log(peer: SocketAddr) -> io::Result<(File, PathBuf)> {
    let directory = PathBuf::from("logs");
    fs::create_dir_all(&directory).await?;
    let timestamp = unix_timestamp_millis();

    for sequence in 0_u8..100 {
        let path = directory.join(format!(
            "session-{timestamp}-{}-{sequence}.log",
            peer.port()
        ));
        match OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)
            .await
        {
            Ok(mut file) => {
                file.write_all(
                    format!("{}\t{peer}\tSESSION_START\n", unix_timestamp_millis()).as_bytes(),
                )
                .await?;
                file.flush().await?;
                return Ok((file, path));
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }

    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "고유한 감사 로그 파일명을 만들지 못했습니다",
    ))
}

async fn write_audit(
    file: &mut File,
    peer: SocketAddr,
    event: &str,
    value: &str,
) -> io::Result<()> {
    let single_line = value.replace(['\r', '\n', '\t'], " ");
    file.write_all(
        format!(
            "{}\t{peer}\t{event}\t{single_line}\n",
            unix_timestamp_millis()
        )
        .as_bytes(),
    )
    .await?;
    file.flush().await
}

fn console_input_channel() -> Receiver<ConsoleInput> {
    let (sender, receiver) = mpsc::channel(32);

    std::thread::spawn(move || {
        let stdin = io::stdin();
        let mut input = stdin.lock();

        loop {
            let mut line = String::new();
            let event = match input.read_line(&mut line) {
                Ok(0) => ConsoleInput::Closed,
                Ok(_) => ConsoleInput::Line(line),
                Err(error) => ConsoleInput::Error(error.to_string()),
            };
            let should_stop = !matches!(event, ConsoleInput::Line(_));
            if sender.blocking_send(event).is_err() || should_stop {
                break;
            }
        }
    });

    receiver
}

async fn network_reader(mut reader: OwnedReadHalf, sender: Sender<NetworkEvent>) {
    loop {
        match read_frame(&mut reader).await {
            Ok(frame) => {
                if sender.send(NetworkEvent::Frame(frame)).await.is_err() {
                    return;
                }
            }
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
                let _ = sender.send(NetworkEvent::Closed).await;
                return;
            }
            Err(error) => {
                let _ = sender.send(NetworkEvent::Error(error.to_string())).await;
                return;
            }
        }
    }
}

async fn accept_authenticated(
    listener: &TcpListener,
    token: &str,
) -> io::Result<(TcpStream, SocketAddr)> {
    loop {
        let (mut socket, peer) = listener.accept().await?;
        socket.set_nodelay(true)?;

        match timeout(HANDSHAKE_TIMEOUT, server_handshake(&mut socket, token)).await {
            Ok(Ok(())) => return Ok((socket, peer)),
            Ok(Err(error)) => {
                eprintln!("[RED-LAB] 인증 실패 연결 폐기: {peer} ({error})");
            }
            Err(_) => {
                eprintln!("[RED-LAB] 핸드셰이크 시간 초과 연결 폐기: {peer}");
            }
        }
    }
}

fn allocate_request_id(next_request_id: &mut u64) -> io::Result<u64> {
    let request_id = *next_request_id;
    *next_request_id = next_request_id
        .checked_add(1)
        .ok_or_else(|| io::Error::other("request ID가 최대값에 도달했습니다"))?;
    Ok(request_id)
}

fn decode_remote_text(output: &[u8]) -> String {
    match std::str::from_utf8(output) {
        Ok(text) => text.to_string(),
        Err(_) => {
            let (decoded, _, _) = EUC_KR.decode(output);
            decoded.into_owned()
        }
    }
}

fn prompt_path(output: &[u8]) -> String {
    let decoded = decode_remote_text(output);
    let path = decoded
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or("<remote>");

    path.chars()
        .map(|character| {
            if character.is_control() {
                '?'
            } else {
                character
            }
        })
        .collect()
}

async fn print_remote_prompt(path: &str) -> io::Result<()> {
    let mut output = tokio::io::stdout();
    output.write_all(format!("PS {path}> ").as_bytes()).await?;
    output.flush().await
}

async fn queue_prompt_request(
    socket_writer: &mut tokio::net::tcp::OwnedWriteHalf,
    pending_requests: &mut HashMap<u64, PendingRequest>,
    next_request_id: &mut u64,
    audit: &mut File,
    peer: SocketAddr,
) -> io::Result<()> {
    let request_id = allocate_request_id(next_request_id)?;
    write_frame(
        socket_writer,
        &Frame::new(
            FrameKind::Command,
            request_id,
            0,
            b"(Get-Location).Path".to_vec(),
        ),
    )
    .await?;
    pending_requests.insert(request_id, PendingRequest::Prompt { output: Vec::new() });
    write_audit(audit, peer, "PROMPT_QUERY", &format!("#{request_id}")).await
}

async fn display_user_text(kind: FrameKind, text: &str) -> io::Result<()> {
    if text.is_empty() {
        return Ok(());
    }

    match kind {
        FrameKind::Stdout => {
            let mut output = tokio::io::stdout();
            output.write_all(text.as_bytes()).await?;
            output.flush().await
        }
        FrameKind::Stderr => {
            let mut output = tokio::io::stderr();
            output.write_all(text.as_bytes()).await?;
            output.flush().await
        }
        _ => Ok(()),
    }
}

async fn session_loop(socket: TcpStream, peer: SocketAddr, audit: &mut File) -> io::Result<String> {
    let (socket_reader, mut socket_writer) = socket.into_split();
    let (network_sender, mut network_events) = mpsc::channel(64);
    let network_task = tokio::spawn(network_reader(socket_reader, network_sender));
    let mut console_input = console_input_channel();
    let mut next_request_id = 1_u64;
    let mut pending_requests = HashMap::new();
    let mut local_closing = false;

    queue_prompt_request(
        &mut socket_writer,
        &mut pending_requests,
        &mut next_request_id,
        audit,
        peer,
    )
    .await?;

    let result: io::Result<String> = async {
        loop {
            tokio::select! {
            input = console_input.recv(), if !local_closing => {
                match input {
                    Some(ConsoleInput::Line(line)) => {
                        let command = line.trim_end_matches(['\r', '\n']);
                        if command == ".disconnect" || command.eq_ignore_ascii_case("exit") {
                            write_audit(audit, peer, "LOCAL_DISCONNECT", command).await?;
                            write_frame(
                                &mut socket_writer,
                                &Frame::new(FrameKind::Close, 0, 0, Vec::new()),
                            ).await?;
                            socket_writer.shutdown().await?;
                            local_closing = true;
                            continue;
                        }

                        if !pending_requests.is_empty() {
                            eprintln!("[RED-LAB] 이전 명령이 아직 실행 중입니다");
                            continue;
                        }

                        if command.trim().is_empty() {
                            queue_prompt_request(
                                &mut socket_writer,
                                &mut pending_requests,
                                &mut next_request_id,
                                audit,
                                peer,
                            ).await?;
                            continue;
                        }

                        let request_id = allocate_request_id(&mut next_request_id)?;
                        write_audit(
                            audit,
                            peer,
                            "COMMAND",
                            &format!("#{request_id} {command}"),
                        ).await?;
                        write_frame(
                            &mut socket_writer,
                            &Frame::new(
                                FrameKind::Command,
                                request_id,
                                0,
                                command.as_bytes().to_vec(),
                            ),
                        ).await?;
                        pending_requests.insert(
                            request_id,
                            PendingRequest::User {
                                stdout: TextBuffer::default(),
                                stderr: TextBuffer::default(),
                                saw_output: false,
                                ended_with_newline: true,
                            },
                        );
                    }
                    Some(ConsoleInput::Closed) | None => {
                        write_audit(audit, peer, "LOCAL_STDIN_CLOSED", "").await?;
                        write_frame(
                            &mut socket_writer,
                            &Frame::new(FrameKind::Close, 0, 0, Vec::new()),
                        ).await?;
                        socket_writer.shutdown().await?;
                        local_closing = true;
                    }
                    Some(ConsoleInput::Error(error)) => {
                        write_audit(audit, peer, "LOCAL_STDIN_ERROR", &error).await?;
                        break Err(io::Error::other(error));
                    }
                }
            }
            event = network_events.recv() => {
                match event {
                    Some(NetworkEvent::Frame(frame)) => {
                        match frame.kind {
                            FrameKind::Stdout | FrameKind::Stderr => {
                                let Some(pending) = pending_requests.get_mut(&frame.request_id) else {
                                    break Err(io::Error::new(
                                        io::ErrorKind::InvalidData,
                                        format!("알 수 없는 request ID의 출력입니다: {}", frame.request_id),
                                    ));
                                };

                                let decoded = match pending {
                                    PendingRequest::User {
                                        stdout,
                                        stderr,
                                        saw_output,
                                        ended_with_newline,
                                    } => {
                                        if !frame.payload.is_empty() {
                                            *saw_output = true;
                                            *ended_with_newline = frame
                                                .payload
                                                .last()
                                                .is_some_and(|byte| matches!(byte, b'\r' | b'\n'));
                                        }
                                        match frame.kind {
                                            FrameKind::Stdout => stdout.push(&frame.payload),
                                            FrameKind::Stderr => stderr.push(&frame.payload),
                                            _ => String::new(),
                                        }
                                    }
                                    PendingRequest::Prompt { output } => {
                                        if frame.kind == FrameKind::Stdout {
                                            output.extend_from_slice(&frame.payload);
                                        }
                                        String::new()
                                    }
                                };

                                display_user_text(frame.kind, &decoded).await?;
                            }
                            FrameKind::Exit => {
                                let Some(pending) = pending_requests.remove(&frame.request_id) else {
                                    break Err(io::Error::new(
                                        io::ErrorKind::InvalidData,
                                        format!("알 수 없는 request ID의 종료입니다: {}", frame.request_id),
                                    ));
                                };

                                match pending {
                                    PendingRequest::User {
                                        mut stdout,
                                        mut stderr,
                                        saw_output,
                                        ended_with_newline,
                                    } => {
                                        display_user_text(FrameKind::Stdout, &stdout.finish()).await?;
                                        display_user_text(FrameKind::Stderr, &stderr.finish()).await?;
                                        write_audit(
                                            audit,
                                            peer,
                                            "COMMAND_EXIT",
                                            &format!("#{} status={}", frame.request_id, frame.status),
                                        ).await?;
                                        if saw_output && !ended_with_newline {
                                            println!();
                                        }
                                        if frame.status != 0 {
                                            eprintln!("[RED-LAB] 종료 코드: {}", frame.status);
                                        }
                                        queue_prompt_request(
                                            &mut socket_writer,
                                            &mut pending_requests,
                                            &mut next_request_id,
                                            audit,
                                            peer,
                                        ).await?;
                                    }
                                    PendingRequest::Prompt { output } => {
                                        write_audit(
                                            audit,
                                            peer,
                                            "PROMPT_EXIT",
                                            &format!("#{} status={}", frame.request_id, frame.status),
                                        ).await?;
                                        let path = if frame.status == 0 {
                                            prompt_path(&output)
                                        } else {
                                            "<remote>".to_string()
                                        };
                                        print_remote_prompt(&path).await?;
                                    }
                                }
                            }
                            FrameKind::Error => {
                                let message = String::from_utf8_lossy(&frame.payload);
                                write_audit(
                                    audit,
                                    peer,
                                    "REMOTE_ERROR",
                                    &format!("#{} {message}", frame.request_id),
                                ).await?;
                                eprintln!(
                                    "\n[RED-LAB] 에이전트 오류 #{}: {message}",
                                    frame.request_id
                                );
                            }
                            unexpected => {
                                break Err(io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    format!("리스너가 받을 수 없는 프레임입니다: {unexpected:?}"),
                                ));
                            }
                        }
                    }
                    Some(NetworkEvent::Closed) => {
                        break Ok(if local_closing {
                            "local disconnect completed".to_string()
                        } else {
                            "agent closed connection".to_string()
                        });
                    }
                    Some(NetworkEvent::Error(error)) => break Err(io::Error::other(error)),
                    None => break Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "네트워크 이벤트 채널이 종료되었습니다",
                    )),
                }
            }
            }
        }
    }
    .await;

    network_task.abort();
    result
}

async fn run_session(socket: TcpStream, peer: SocketAddr) -> io::Result<()> {
    let (mut audit, audit_path) = create_audit_log(peer).await?;
    println!("[RED-LAB] 승인된 에이전트 연결: {peer}");
    println!("[RED-LAB] 명령 감사 로그: {}", audit_path.display());

    let result = session_loop(socket, peer, &mut audit).await;
    let end_status = if result.is_ok() {
        "SESSION_END"
    } else {
        "SESSION_ERROR"
    };
    let owned_message = match &result {
        Ok(message) => message.clone(),
        Err(error) => error.to_string(),
    };
    write_audit(&mut audit, peer, end_status, &owned_message).await?;

    match result {
        Ok(message) => {
            println!("\n[RED-LAB] 세션 종료: {message}");
            Ok(())
        }
        Err(error) => Err(error),
    }
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let (address, token, configured_session) = runtime_settings()?;
    let listener = TcpListener::bind(address).await?;
    let bound_address = listener.local_addr()?;

    if let Some(session_id) = configured_session {
        println!("[RED-LAB] 번들 세션: {session_id}");
    }
    println!("[RED-LAB] PowerShell 실습 리스너: {bound_address}");
    println!(
        "[RED-LAB] 인증 전 연결 제한시간: {}초",
        HANDSHAKE_TIMEOUT.as_secs()
    );
    println!("[RED-LAB] 로컬 종료 명령: exit 또는 .disconnect");

    let (socket, peer) = accept_authenticated(&listener, &token).await?;
    run_session(socket, peer).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_private_and_public_looking_bind_addresses() {
        assert_eq!(
            parse_bind_address("172.16.21.172", "14444").expect("private address"),
            "172.16.21.172:14444".parse().expect("socket address")
        );
        assert_eq!(
            parse_bind_address("198.51.100.25", "14444").expect("virtual public address"),
            "198.51.100.25:14444".parse().expect("socket address")
        );
    }

    #[test]
    fn rejects_invalid_address_and_zero_port() {
        assert!(parse_bind_address("not-an-ip", "14444").is_err());
        assert!(parse_bind_address("127.0.0.1", "0").is_err());
    }

    #[test]
    fn builds_clean_powershell_prompt_path() {
        assert_eq!(
            prompt_path(b"C:\\Users\\cacti-op\r\n"),
            "C:\\Users\\cacti-op"
        );
        assert_eq!(prompt_path(b"\r\n"), "<remote>");
        assert_eq!(prompt_path(b"C:\\Lab\x1b[31m\r\n"), "C:\\Lab?[31m");
    }

    #[test]
    fn decodes_utf8_and_windows_949_output() {
        assert_eq!(decode_remote_text("한글".as_bytes()), "한글");
        assert_eq!(decode_remote_text(&[0xc7, 0xd1, 0xb1, 0xdb]), "한글");

        let mut buffer = TextBuffer::default();
        assert_eq!(buffer.push(&[0xc7]), "");
        assert_eq!(buffer.push(&[0xd1, 0xb1, 0xdb, b'\r', b'\n']), "한글\r\n");
        assert_eq!(buffer.finish(), "");
    }
}
