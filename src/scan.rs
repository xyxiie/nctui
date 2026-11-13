//! Runs nmap, streams its XML output and probes discovered hosts.

use std::collections::VecDeque;
use std::fs;
use std::io::{BufRead, BufReader, Read};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::AtomicBool;
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use quick_xml::events::{BytesStart, Event};
use quick_xml::Reader;

use crate::fast;
use crate::mc;

#[derive(Debug, Clone)]
pub enum ScanEvent {
    Host { addr: String, port: u16 },
    Progress(f32),
    Info(String),
    Server { addr: String, result: Result<mc::Status, String> },
    Done(String),
    Failed(String),
}

#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub nmap: bool,
    pub sample_percent: u8,
    pub stop_after: usize,
    pub concurrency: usize,
    pub timeout: Duration,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            nmap: false,
            sample_percent: 100,
            stop_after: 0,
            concurrency: 0,
            timeout: Duration::from_millis(400),
        }
    }
}

pub fn spawn_scan(
    target: String,
    port: u16,
    options: ScanOptions,
    tx: Sender<ScanEvent>,
    cancel: Arc<AtomicBool>,
) {
    if !options.nmap && supports_fast(&target) {
        thread::spawn(move || run_fast(target, port, options, tx, cancel));
    } else {
        thread::spawn(move || run_nmap(target, port, tx));
    }
}

/// True when the target can be handled by the built-in IPv4 connect scanner.
pub fn supports_fast(target: &str) -> bool {
    country_code(target).is_some() || fast::Range::parse(target).is_some()
}

pub fn spawn_probe(addr: String, port: u16, tx: Sender<ScanEvent>) {
    let _ = probe_thread(addr, port, tx);
}

pub(crate) fn probe_thread(addr: String, port: u16, tx: Sender<ScanEvent>) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let result = mc::status(&addr, port).map_err(|error| error.0);
        let _ = tx.send(ScanEvent::Server { addr, result });
    })
}

fn run_fast(
    target: String,
    port: u16,
    options: ScanOptions,
    tx: Sender<ScanEvent>,
    cancel: Arc<AtomicBool>,
) {
    let lines = if let Some(code) = country_code(&target) {
        let _ = tx.send(ScanEvent::Info(format!(
            "Downloading IPv4 ranges for {code}…"
        )));
        match fetch_country_ranges(&code, &tx) {
            Ok(ranges) => ranges,
            Err(message) => {
                let _ = tx.send(ScanEvent::Failed(message));
                return;
            }
        }
    } else {
        vec![target]
    };

    let ranges: Vec<fast::Range> = lines
        .iter()
        .filter_map(|line| fast::Range::parse(line))
        .collect();
    if ranges.is_empty() {
        let _ = tx.send(ScanEvent::Failed(
            "no IPv4 CIDR ranges to scan (use nmap for hostnames and range expressions)"
                .to_string(),
        ));
        return;
    }

    match fast::scan(ranges, port, &options, tx.clone(), cancel) {
        Ok(summary) => {
            let seconds = summary.elapsed.as_secs_f64();
            let rate = if seconds > 0.0 {
                summary.attempted as f64 / seconds
            } else {
                0.0
            };
            let outcome = if summary.cancelled {
                "stopped".to_string()
            } else if summary.limit_reached {
                format!("stopped after {} open port(s)", summary.open)
            } else {
                "finished".to_string()
            };
            let _ = tx.send(ScanEvent::Done(format!(
                "Fast scan {outcome} — {} addresses in {:.1}s ({}/s), {} open port(s)",
                with_commas(summary.attempted),
                seconds,
                with_commas(rate as u64),
                summary.open
            )));
        }
        Err(message) => {
            let _ = tx.send(ScanEvent::Failed(message));
        }
    }
}

fn run_nmap(target: String, port: u16, tx: Sender<ScanEvent>) {
    let mut target_file: Option<TargetFile> = None;

    if let Some(code) = country_code(&target) {
        let _ = tx.send(ScanEvent::Info(format!(
            "Downloading IPv4 ranges for {code}…"
        )));
        let ranges = match fetch_country_ranges(&code, &tx) {
            Ok(ranges) => ranges,
            Err(message) => {
                let _ = tx.send(ScanEvent::Failed(message));
                return;
            }
        };
        match write_target_list(&code, &ranges) {
            Ok(file) => {
                let _ = tx.send(ScanEvent::Info(format!(
                    "{code}: {} IPv4 ranges — scanning (this can take a long time)…",
                    ranges.len()
                )));
                target_file = Some(file);
            }
            Err(message) => {
                let _ = tx.send(ScanEvent::Failed(message));
                return;
            }
        }
    }

    let mut command = Command::new("nmap");
    command.args([
        "-n",
        "-T4",
        "--open",
        "--stats-every",
        "1s",
        "-p",
        &port.to_string(),
        "-oX",
        "-",
    ]);
    match &target_file {
        Some(file) => {
            command.arg("-iL").arg(&file.0);
        }
        None => {
            command.arg(&target);
        }
    }
    let child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();

    let mut child = match child {
        Ok(child) => child,
        Err(error) => {
            let message = if error.kind() == std::io::ErrorKind::NotFound {
                "nmap was not found on PATH — install nmap first".to_string()
            } else {
                format!("could not start nmap: {error}")
            };
            let _ = tx.send(ScanEvent::Failed(message));
            return;
        }
    };

    let stderr_log = Arc::new(Mutex::new(VecDeque::<String>::new()));
    let stderr_handle = child.stderr.take().map(|stderr| {
        let log = stderr_log.clone();
        let tx = tx.clone();
        thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                if let Some(percent) = parse_progress(&line) {
                    let _ = tx.send(ScanEvent::Progress(percent));
                }
                let line = line.trim().to_string();
                if line.is_empty() {
                    continue;
                }
                let mut log = log.lock().unwrap();
                if log.len() == 32 {
                    log.pop_front();
                }
                log.push_back(line);
            }
        })
    });

    let Some(stdout) = child.stdout.take() else {
        let _ = tx.send(ScanEvent::Failed("nmap stdout was unavailable".to_string()));
        return;
    };

    let mut found = 0usize;
    let mut probes = Vec::new();
    let parse_result;
    {
        let tx_host = tx.clone();
        parse_result = parse_hosts(BufReader::new(stdout), port, |addr| {
            found += 1;
            let _ = tx_host.send(ScanEvent::Host {
                addr: addr.clone(),
                port,
            });
            probes.push(probe_thread(addr, port, tx.clone()));
        });
        if parse_result.is_err() {
            let _ = child.kill();
        }
    }

    let exit_status = child.wait();
    if let Some(handle) = stderr_handle {
        let _ = handle.join();
    }
    for probe in probes {
        let _ = probe.join();
    }

    if let Err(message) = parse_result {
        let _ = tx.send(ScanEvent::Failed(message));
        return;
    }

    match exit_status {
        Ok(status) if status.success() => {
            let _ = tx.send(ScanEvent::Done(format!(
                "Scan finished — {found} host(s) with TCP {port} open"
            )));
        }
        Ok(status) => {
            let detail = stderr_log
                .lock()
                .ok()
                .and_then(|log| log.back().cloned())
                .unwrap_or_default();
            let message = if detail.is_empty() {
                format!("nmap exited with status {status}")
            } else {
                format!("nmap exited with status {status}: {detail}")
            };
            let _ = tx.send(ScanEvent::Failed(message));
        }
        Err(error) => {
            let _ = tx.send(ScanEvent::Failed(format!(
                "failed while waiting for nmap: {error}"
            )));
        }
    }
}

fn parse_hosts<R: BufRead, F: FnMut(String)>(
    reader: R,
    port: u16,
    mut on_host: F,
) -> Result<(), String> {
    let mut xml = Reader::from_reader(reader);
    xml.config_mut().trim_text(true);

    let mut buffer = Vec::new();
    let mut in_host = false;
    let mut up = false;
    let mut open = false;
    let mut port_matches = false;
    let mut address: Option<String> = None;

    loop {
        let event = xml.read_event_into(&mut buffer);
        match event {
            Ok(Event::Start(element)) => {
                if element.name().as_ref() == b"host" {
                    in_host = true;
                    up = false;
                    open = false;
                    port_matches = false;
                    address = None;
                } else if in_host {
                    handle_element(&element, port, &mut up, &mut open, &mut port_matches, &mut address);
                }
            }
            Ok(Event::Empty(element)) => {
                if in_host {
                    handle_element(&element, port, &mut up, &mut open, &mut port_matches, &mut address);
                }
            }
            Ok(Event::End(element)) => {
                if element.name().as_ref() == b"host" {
                    if in_host && up && open {
                        if let Some(address) = address.take() {
                            on_host(address);
                        }
                    }
                    in_host = false;
                }
            }
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(error) => return Err(format!("could not parse nmap XML: {error}")),
        }
        buffer.clear();
    }

    Ok(())
}

fn handle_element(
    element: &BytesStart,
    port: u16,
    up: &mut bool,
    open: &mut bool,
    port_matches: &mut bool,
    address: &mut Option<String>,
) {
    match element.name().as_ref() {
        b"status" => {
            if let Some(state) = attribute(element, b"state") {
                *up = state == "up";
            }
        }
        b"address" => {
            if address.is_none() {
                let kind = attribute(element, b"addrtype").unwrap_or_default();
                if kind != "mac" {
                    if let Some(addr) = attribute(element, b"addr") {
                        *address = Some(addr);
                    }
                }
            }
        }
        b"port" => {
            *port_matches = attribute(element, b"portid")
                .and_then(|value| value.parse::<u16>().ok())
                == Some(port);
        }
        b"state" => {
            if *port_matches && attribute(element, b"state").as_deref() == Some("open") {
                *open = true;
            }
        }
        _ => {}
    }
}

fn attribute(element: &BytesStart, key: &[u8]) -> Option<String> {
    element
        .attributes()
        .with_checks(false)
        .flatten()
        .find(|attribute| attribute.key.as_ref() == key)
        .and_then(|attribute| attribute.unescape_value().ok().map(|value| value.into_owned()))
}

pub(crate) fn with_commas(value: u64) -> String {
    let digits = value.to_string();
    let length = digits.len();
    let mut formatted = String::with_capacity(length + length / 3);
    for (index, digit) in digits.chars().enumerate() {
        if index > 0 && (length - index) % 3 == 0 {
            formatted.push(',');
        }
        formatted.push(digit);
    }
    formatted
}

fn parse_progress(line: &str) -> Option<f32> {
    let start = line.find("About ")? + "About ".len();
    let rest = &line[start..];
    let end = rest.find("% done")?;
    rest[..end].trim().parse().ok()
}

/// A temporary nmap target list, removed when the scan finishes.
struct TargetFile(PathBuf);

impl Drop for TargetFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

/// Returns the uppercase country code if the input is exactly two letters.
pub fn country_code(value: &str) -> Option<String> {
    let value = value.trim();
    (value.len() == 2 && value.chars().all(|c| c.is_ascii_alphabetic()))
        .then(|| value.to_ascii_uppercase())
}

const RANGE_FETCH_ATTEMPTS: u32 = 8;
const MAX_RANGE_BYTES: usize = 32 * 1024 * 1024;

fn fetch_country_ranges(code: &str, tx: &Sender<ScanEvent>) -> Result<Vec<String>, String> {
    let url = format!(
        "https://www.ipdeny.com/ipblocks/data/aggregated/{}-aggregated.zone",
        code.to_ascii_lowercase()
    );
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(10))
        .timeout_read(Duration::from_secs(20))
        .user_agent(concat!("nctui/", env!("CARGO_PKG_VERSION")))
        .build();
    fetch_zone(&agent, &url, code, tx)
}

/// Downloads and parses one zone file.
///
/// ipdeny drops slow connections partway through the larger zone files, so an
/// interrupted download resumes from the last received byte with a ranged
/// request instead of failing the whole scan.
fn fetch_zone(
    agent: &ureq::Agent,
    url: &str,
    code: &str,
    tx: &Sender<ScanEvent>,
) -> Result<Vec<String>, String> {
    let mut body: Vec<u8> = Vec::new();
    let mut total: Option<usize> = None;
    let mut stalls = 0;
    let mut last_error = String::new();

    for attempt in 1..=RANGE_FETCH_ATTEMPTS {
        let _ = tx.send(ScanEvent::Info(download_status(code, body.len(), total)));
        let received_before = body.len();

        match download_once(agent, url, code, &mut body, &mut total) {
            Ok(()) if total.map_or(true, |total| body.len() >= total) => {
                let ranges = parse_ranges(&String::from_utf8_lossy(&body));
                if ranges.is_empty() {
                    return Err(format!("no IPv4 ranges found for country code {code}"));
                }
                return Ok(ranges);
            }
            Ok(()) => {
                last_error =
                    format!("could not read IPv4 ranges for {code}: connection closed early");
            }
            Err(message) => last_error = message,
        }

        if body.len() == received_before {
            // The server is not sending anything more; do not keep retrying.
            stalls += 1;
            if stalls >= 2 {
                break;
            }
            thread::sleep(Duration::from_millis(500));
        } else {
            stalls = 0;
        }

        if attempt == RANGE_FETCH_ATTEMPTS {
            break;
        }
    }

    Err(format!("{last_error} (download incomplete)"))
}

fn download_status(code: &str, received: usize, total: Option<usize>) -> String {
    match total {
        Some(total) if total > 0 => format!(
            "Downloading IPv4 ranges for {code}… {}% ({}/{} KB)",
            (received * 100 / total).min(100),
            received / 1024,
            total / 1024
        ),
        _ => format!(
            "Downloading IPv4 ranges for {code}… {} KB",
            received / 1024
        ),
    }
}

/// Appends the next part of the zone file to `body`, continuing where the last
/// attempt stopped. Returns `Ok(())` once the connection ends, which may still
/// be a truncated body; the caller checks that against the content length.
fn download_once(
    agent: &ureq::Agent,
    url: &str,
    code: &str,
    body: &mut Vec<u8>,
    total: &mut Option<usize>,
) -> Result<(), String> {
    let response = match agent
        .get(url)
        .set("Range", &format!("bytes={}-", body.len()))
        .call()
    {
        Ok(response) => response,
        // Requested offset is past the end: the file is already complete.
        Err(ureq::Error::Status(416, _)) if !body.is_empty() => return Ok(()),
        Err(ureq::Error::Status(404, _)) => {
            return Err(format!("unknown country code {code} (no IPv4 ranges found)"));
        }
        Err(error) => {
            return Err(format!("could not download IPv4 ranges for {code}: {error}"));
        }
    };

    // 206 continues the file; a 200 means the server ignored the range and is
    // sending the whole file again.
    if response.status() != 206 {
        body.clear();
    }
    if let Some(length) = response
        .header("content-length")
        .and_then(|value| value.parse::<usize>().ok())
    {
        *total = Some(body.len() + length);
    }

    let mut reader = response.into_reader();
    let mut chunk = [0u8; 16 * 1024];
    loop {
        match reader.read(&mut chunk) {
            Ok(0) => return Ok(()),
            Ok(count) => {
                body.extend_from_slice(&chunk[..count]);
                if body.len() > MAX_RANGE_BYTES {
                    return Err(format!("IPv4 range list for {code} is unexpectedly large"));
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => {
                return Err(format!("could not read IPv4 ranges for {code}: {error}"));
            }
        }
    }
}

fn parse_ranges(body: &str) -> Vec<String> {
    body.lines()
        .map(str::trim)
        .filter(|line| {
            !line.is_empty()
                && !line.starts_with('#')
                && line.contains('/')
                && !line.contains(char::is_whitespace)
        })
        .map(str::to_string)
        .collect()
}

fn write_target_list(code: &str, ranges: &[String]) -> Result<TargetFile, String> {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    let path = std::env::temp_dir().join(format!(
        "nctui-{code}-{}-{unique}.txt",
        std::process::id()
    ));
    fs::write(&path, ranges.join("\n"))
        .map_err(|error| format!("could not write nmap target list: {error}"))?;
    Ok(TargetFile(path))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Write};
    use std::net::TcpListener;
    use std::sync::mpsc;

    #[test]
    fn resumes_an_interrupted_range_download() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let zone = "10.0.0.0/8\n192.168.0.0/16\n";
        let (tx, _rx) = mpsc::channel();

        // Every response delivers only part of the remaining body and closes,
        // like ipdeny does on large zone files.
        thread::spawn(move || {
            let mut sent = 0usize;
            while sent < zone.len() {
                let (mut socket, _) = listener.accept().unwrap();
                let mut reader = BufReader::new(socket.try_clone().unwrap());
                let mut request = String::new();
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                        break;
                    }
                    request.push_str(&line);
                }

                let start: usize = request
                    .lines()
                    .find_map(|line| {
                        line.to_ascii_lowercase()
                            .strip_prefix("range: bytes=")
                            .and_then(|value| value.trim_end_matches('-').parse().ok())
                    })
                    .unwrap_or(0);
                assert_eq!(start, sent, "resume must continue at the received byte");

                let rest = &zone[start..];
                socket
                    .write_all(
                        format!(
                            "HTTP/1.1 206 Partial Content\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                            rest.len()
                        )
                        .as_bytes(),
                    )
                    .unwrap();
                let cut = (rest.len() / 2).max(1);
                socket.write_all(&rest.as_bytes()[..cut]).unwrap();
                sent += cut;
            }
        });

        let agent = ureq::AgentBuilder::new().build();
        let url = format!("http://{address}/zone.zone");
        let ranges = fetch_zone(&agent, &url, "ZZ", &tx).unwrap();
        assert_eq!(ranges, vec!["10.0.0.0/8", "192.168.0.0/16"]);
    }

    #[test]
    fn finds_only_hosts_with_the_scanned_port_open() {
        let xml = r#"<?xml version="1.0"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap">
  <host>
    <status state="up" reason="echo-reply"/>
    <address addr="10.0.0.5" addrtype="ipv4"/>
    <address addr="AA:BB:CC:DD:EE:FF" addrtype="mac"/>
    <ports>
      <port protocol="tcp" portid="25565">
        <state state="open" reason="syn-ack"/>
      </port>
    </ports>
  </host>
  <host>
    <status state="down"/>
    <address addr="10.0.0.6" addrtype="ipv4"/>
  </host>
  <host>
    <status state="up"/>
    <address addr="10.0.0.7" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
      </port>
    </ports>
  </host>
  <host>
    <status state="up"/>
    <address addr="10.0.0.8" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="25565">
        <state state="closed"/>
      </port>
    </ports>
  </host>
</nmaprun>"#;

        let mut hosts = Vec::new();
        parse_hosts(Cursor::new(xml), 25565, |addr| hosts.push(addr)).unwrap();
        assert_eq!(hosts, vec!["10.0.0.5"]);
    }

    #[test]
    fn recognizes_country_codes() {
        assert_eq!(country_code("de"), Some("DE".to_string()));
        assert_eq!(country_code(" US "), Some("US".to_string()));
        assert_eq!(country_code("192.168.1.0/24"), None);
        assert_eq!(country_code("server.example"), None);
        assert_eq!(country_code("12"), None);
    }

    #[test]
    fn parses_country_range_file() {
        let body = "# comment\n\n2.28.0.0/14\ninvalid line\n2.56.11.0/24\n";
        assert_eq!(parse_ranges(body), vec!["2.28.0.0/14", "2.56.11.0/24"]);
    }

    #[test]
    fn picks_fast_scanner_for_ipv4_and_countries() {
        assert!(supports_fast("192.168.1.0/24"));
        assert!(supports_fast("10.0.0.1"));
        assert!(supports_fast("de"));
        assert!(!supports_fast("example.com"));
        assert!(!supports_fast("10.0.0.1-50"));
        assert!(!supports_fast("10.0.0.0/24,10.0.1.0/24"));
    }

    #[test]
    fn formats_thousands() {
        assert_eq!(with_commas(0), "0");
        assert_eq!(with_commas(999), "999");
        assert_eq!(with_commas(1_234_567), "1,234,567");
    }

    #[test]
    fn parses_nmap_progress() {
        let line = "Stats: 0:00:03 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan\nAbout 12.34% done";
        assert_eq!(parse_progress(line), Some(12.34));
        assert_eq!(parse_progress("Nmap done: 1 IP address"), None);
    }
}
