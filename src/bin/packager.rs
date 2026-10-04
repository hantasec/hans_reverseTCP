use std::fs;
use std::io;
use std::io::Write as _;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use powershell_reverse_lab::{
    AGENT_CONFIG_FILE, HOST_CONFIG_FILE, LabConfig, parse_socket_address, write_config,
};

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

fn prompt_address() -> io::Result<SocketAddr> {
    loop {
        let ip_text = prompt("호스트 IP: ")?;
        let port_text = prompt("호스트 포트: ")?;
        let parsed = (|| {
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
        })();

        match parsed {
            Ok(address) => return Ok(address),
            Err(error) => eprintln!("[RED-LAB] 입력 오류: {error}. 다시 입력하세요."),
        }
    }
}

fn random_bytes<const N: usize>() -> io::Result<[u8; N]> {
    let mut bytes = [0_u8; N];
    getrandom::fill(&mut bytes)
        .map_err(|error| io::Error::other(format!("난수 생성 실패: {error}")))?;
    Ok(bytes)
}

fn session_id() -> io::Result<String> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let suffix = random_bytes::<4>()?
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Ok(format!("{timestamp}-{suffix}"))
}

fn source_binary(directory: &Path, stem: &str) -> PathBuf {
    if cfg!(windows) {
        directory.join(format!("{stem}.exe"))
    } else {
        directory.join(stem)
    }
}

fn destination_binary(directory: &Path, stem: &str) -> PathBuf {
    source_binary(directory, stem)
}

fn ensure_source_binary(path: &Path) -> io::Result<()> {
    if path.is_file() {
        return Ok(());
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!(
            "번들에 넣을 실행 파일이 없습니다: {}. 먼저 cargo build --release --bins를 실행하세요.",
            path.display()
        ),
    ))
}

fn create_bundle(address: SocketAddr) -> io::Result<PathBuf> {
    let current_executable = std::env::current_exe()?;
    let binary_directory = current_executable
        .parent()
        .ok_or_else(|| io::Error::other("packager 실행 파일 디렉터리를 찾지 못했습니다"))?;
    let listener_source = source_binary(binary_directory, "listener");
    let agent_source = source_binary(binary_directory, "agent");
    ensure_source_binary(&listener_source)?;
    ensure_source_binary(&agent_source)?;

    let session_id = session_id()?;
    let token = BASE64.encode(random_bytes::<32>()?);
    let bundle_root = std::env::current_dir()?
        .join("dist")
        .join(format!("session-{session_id}"));
    let host_directory = bundle_root.join("host");
    let agent_directory = bundle_root.join("agent");
    fs::create_dir_all(&host_directory)?;
    fs::create_dir_all(&agent_directory)?;

    let host_binary = destination_binary(&host_directory, "host");
    let agent_binary = destination_binary(&agent_directory, "agent");
    fs::copy(listener_source, &host_binary)?;
    fs::copy(agent_source, &agent_binary)?;

    let address_text = address.to_string();
    let host_config = LabConfig {
        version: 1,
        role: "host".to_string(),
        session_id: session_id.clone(),
        address: address_text.clone(),
        token: token.clone(),
    };
    let agent_config = LabConfig {
        version: 1,
        role: "agent".to_string(),
        session_id: session_id.clone(),
        address: address_text.clone(),
        token,
    };
    host_config.validate("host")?;
    agent_config.validate("agent")?;
    write_config(&host_directory.join(HOST_CONFIG_FILE), &host_config)?;
    write_config(&agent_directory.join(AGENT_CONFIG_FILE), &agent_config)?;

    let instructions = format!(
        "RED PowerShell lab bundle\r\n\
Session: {session_id}\r\n\
Address: {address_text}\r\n\r\n\
1. Copy the host directory to the authorized listener system and run host.\r\n\
2. Copy the agent directory to the approved Windows 10 VM and run agent.exe.\r\n\
3. Keep both TOML files beside their executable.\r\n\
4. The TOML files contain a lab session token; delete the bundle after the exercise.\r\n"
    );
    fs::write(bundle_root.join("README.txt"), instructions)?;

    Ok(bundle_root)
}

fn main() -> io::Result<()> {
    println!("[RED-LAB] 승인된 GNS 격리망용 번들 생성기");
    println!("[RED-LAB] GNS 가상 공인 IP를 포함한 IP 리터럴을 사용할 수 있습니다.");
    let address = prompt_address()?;
    let bundle = create_bundle(address)?;

    println!("[RED-LAB] 번들 생성 완료: {}", bundle.display());
    println!("[RED-LAB] host 폴더는 리스너 장비, agent 폴더는 Windows 10 VM에 배포하세요.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_binary_uses_platform_suffix() {
        let path = source_binary(Path::new("bin"), "agent");
        if cfg!(windows) {
            assert!(path.ends_with("agent.exe"));
        } else {
            assert!(path.ends_with("agent"));
        }
    }

    #[test]
    fn generated_session_id_is_nonempty() {
        let value = session_id().expect("session ID");
        assert!(value.contains('-'));
    }
}
