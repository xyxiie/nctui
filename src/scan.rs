//! Runs nmap, streams its XML output and probes discovered hosts.

use std::collections::VecDeque;
use std::fs;
use std::io::{self, BufRead, BufReader, Read};
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use quick_xml::events::{BytesStart, Event};
use quick_xml::Reader;

use crate::fast;
use crate::mc;

/// Default scan target, shared by the UI and `--help`.
pub const DEFAULT_TARGET: &str = "192.168.1.0/24";

#[derive(Debug, Clone)]
pub enum ScanEvent {
    Host { addr: String, port: u16 },
    Progress(f32),
    Info(String),
    Server {
        addr: String,
        port: u16,
        result: Result<mc::Status, String>,
    },
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
) -> thread::JoinHandle<()> {
    if !options.nmap && supports_fast(&target) {
        thread::spawn(move || run_fast(target, port, options, tx, cancel))
    } else {
        thread::spawn(move || run_nmap(target, port, tx, cancel))
    }
}

/// True when the target can be handled by the built-in IPv4 connect scanner.
pub fn supports_fast(target: &str) -> bool {
    country_code(target).is_some() || fast::Range::parse(target).is_some()
}

pub fn spawn_probe(addr: String, port: u16, tx: Sender<ScanEvent>) {
    let _ = probe_thread(addr, port, tx);
}

pub(crate) fn probe_thread(
    addr: String,
    port: u16,
    tx: Sender<ScanEvent>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let result = mc::status(&addr, port).map_err(|error| error.0);
        let _ = tx.send(ScanEvent::Server { addr, port, result });
    })
}

/// Concurrent Minecraft probes. Each probe keeps a socket and a thread busy, so
/// the pool is fixed-size instead of one thread (and one retained handle) per
/// open port.
pub(crate) const PROBE_CONCURRENCY: usize = 64;

type ProbeJob = Box<dyn FnOnce() + Send>;

/// A fixed-size worker pool for blocking probe jobs.
pub(crate) struct WorkerPool {
    sender: Mutex<Option<mpsc::Sender<ProbeJob>>>,
    receiver: Arc<Mutex<mpsc::Receiver<ProbeJob>>>,
    workers: Mutex<Vec<thread::JoinHandle<()>>>,
    limit: usize,
}

impl WorkerPool {
    pub(crate) fn new(limit: usize) -> Self {
        let (sender, receiver) = mpsc::channel();
        Self {
            sender: Mutex::new(Some(sender)),
            receiver: Arc::new(Mutex::new(receiver)),
            workers: Mutex::new(Vec::new()),
            limit: limit.max(1),
        }
    }

    /// Queues `job`, adding a worker per job until the limit is reached.
    pub(crate) fn submit(&self, job: impl FnOnce() + Send + 'static) {
        let mut workers = match self.workers.lock() {
            Ok(workers) => workers,
            Err(_) => return,
        };
        if workers.len() < self.limit {
            let receiver = Arc::clone(&self.receiver);
            workers.push(thread::spawn(move || loop {
                let job = match receiver.lock() {
                    Ok(receiver) => receiver.recv(),
                    Err(_) => return,
                };
                match job {
                    Ok(job) => job(),
                    Err(_) => return,
                }
            }));
        }
        drop(workers);

        let sender = self.sender.lock().ok();
        if let Some(Some(sender)) = sender.as_deref() {
            let _ = sender.send(Box::new(job));
        }
    }

    /// Closes the queue and waits for the running probes.
    pub(crate) fn finish(&self) {
        if let Ok(mut sender) = self.sender.lock() {
            sender.take();
        }
        let mut workers = match self.workers.lock() {
            Ok(workers) => workers,
            Err(_) => return,
        };
        for worker in workers.drain(..) {
            let _ = worker.join();
        }
    }
}

/// Queues one Minecraft status probe for `addr:port` on the worker pool.
pub(crate) fn queue_probe(pool: &WorkerPool, addr: String, port: u16, tx: Sender<ScanEvent>) {
    pool.submit(move || {
        let result = mc::status(&addr, port).map_err(|error| error.0);
        let _ = tx.send(ScanEvent::Server { addr, port, result });
    });
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
            let _ = tx.send(ScanEvent::Done(fast_done_message(&summary)));
        }
        Err(message) => {
            let _ = tx.send(ScanEvent::Failed(message));
        }
    }
}

/// The final status line for a fast scan, including resource failures.
fn fast_done_message(summary: &fast::Summary) -> String {
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
    let mut message = format!(
        "Fast scan {outcome} — {} addresses in {:.1}s ({}/s), {} open port(s)",
        with_commas(summary.attempted),
        seconds,
        with_commas(rate as u64),
        summary.open
    );
    if summary.resource_failures > 0 {
        message.push_str(&format!(
            " — {} probes failed due to resource limits",
            with_commas(summary.resource_failures as u64)
        ));
    }
    message
}

fn run_nmap(target: String, port: u16, tx: Sender<ScanEvent>, cancel: Arc<AtomicBool>) {
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
        let _ = child.kill();
        let _ = child.wait();
        let _ = tx.send(ScanEvent::Failed("nmap stdout was unavailable".to_string()));
        return;
    };

    // The guard kills and reaps nmap on every return path; the watcher lets `x`
    // stop a scan that is producing no output at all.
    let child = NmapChild::new(child);
    let finished = Arc::new(AtomicBool::new(false));
    let watcher = {
        let slot = child.handle();
        let cancel = Arc::clone(&cancel);
        let finished = Arc::clone(&finished);
        thread::spawn(move || watch_cancel(slot, cancel, finished))
    };

    let probes = WorkerPool::new(PROBE_CONCURRENCY);
    let mut found = 0usize;
    let parse_result;
    {
        let tx_host = tx.clone();
        parse_result = parse_hosts(BufReader::new(stdout), port, |addr| {
            found += 1;
            let _ = tx_host.send(ScanEvent::Host {
                addr: addr.clone(),
                port,
            });
            queue_probe(&probes, addr, port, tx.clone());
        });
        if parse_result.is_err() {
            child.kill();
        }
    }

    let exit_status = child.wait();
    finished.store(true, Ordering::Relaxed);
    let _ = watcher.join();
    if let Some(handle) = stderr_handle {
        let _ = handle.join();
    }

    if let Err(message) = parse_result {
        let _ = tx.send(ScanEvent::Failed(message));
        return;
    }

    if cancel.load(Ordering::Relaxed) {
        let _ = tx.send(ScanEvent::Done(format!(
            "nmap scan stopped — {found} host(s) with TCP {port} open so far"
        )));
        return;
    }

    probes.finish();

    match exit_status {
        Some(Ok(status)) if status.success() => {
            let _ = tx.send(ScanEvent::Done(format!(
                "Scan finished — {found} host(s) with TCP {port} open"
            )));
        }
        Some(Ok(status)) => {
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
        Some(Err(error)) => {
            let _ = tx.send(ScanEvent::Failed(format!(
                "failed while waiting for nmap: {error}"
            )));
        }
        None => {
            let _ = tx.send(ScanEvent::Failed(
                "nmap was stopped before it exited".to_string(),
            ));
        }
    }
}

/// Owns the nmap child so it is always killed and reaped, on every return path.
struct NmapChild {
    slot: Arc<Mutex<Option<Child>>>,
}

impl NmapChild {
    fn new(child: Child) -> Self {
        Self {
            slot: Arc::new(Mutex::new(Some(child))),
        }
    }

    fn handle(&self) -> Arc<Mutex<Option<Child>>> {
        Arc::clone(&self.slot)
    }

    fn kill(&self) {
        kill_child(&self.slot);
    }

    fn wait(&self) -> Option<io::Result<ExitStatus>> {
        self.slot
            .lock()
            .ok()
            .and_then(|mut slot| slot.take())
            .map(|mut child| child.wait())
    }
}

impl Drop for NmapChild {
    fn drop(&mut self) {
        kill_child(&self.slot);
    }
}

fn kill_child(slot: &Arc<Mutex<Option<Child>>>) {
    let child = slot.lock().ok().and_then(|mut slot| slot.take());
    if let Some(mut child) = child {
        let _ = child.kill();
        let _ = child.wait();
    }
}

/// Kills nmap as soon as the scan is cancelled, even when it prints no hosts.
fn watch_cancel(
    slot: Arc<Mutex<Option<Child>>>,
    cancel: Arc<AtomicBool>,
    finished: Arc<AtomicBool>,
) {
    while !finished.load(Ordering::Relaxed) {
        if cancel.load(Ordering::Relaxed) {
            kill_child(&slot);
            return;
        }
        thread::sleep(Duration::from_millis(100));
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
            Ok(true) => {
                let ranges = parse_ranges(&String::from_utf8_lossy(&body));
                if ranges.is_empty() {
                    return Err(format!("no IPv4 ranges found for country code {code}"));
                }
                return Ok(ranges);
            }
            Ok(false) => {
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
/// attempt stopped.
///
/// Returns whether the body is complete: the content length must be satisfied,
/// or, when the server sends no length, the body has to end on a line boundary
/// so a connection that closes early cannot look like a whole zone file.
fn download_once(
    agent: &ureq::Agent,
    url: &str,
    code: &str,
    body: &mut Vec<u8>,
    total: &mut Option<usize>,
) -> Result<bool, String> {
    let response = match agent
        .get(url)
        .set("Range", &format!("bytes={}-", body.len()))
        .call()
    {
        Ok(response) => response,
        // Requested offset is past the end: the file is already complete.
        Err(ureq::Error::Status(416, _)) if !body.is_empty() => {
            return Ok(body_is_complete(body, *total));
        }
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
            Ok(0) => return Ok(body_is_complete(body, *total)),
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

/// Whether a downloaded body is known to be whole.
fn body_is_complete(body: &[u8], total: Option<usize>) -> bool {
    match total {
        Some(total) => body.len() >= total,
        None => body.last() == Some(&b'\n'),
    }
}

/// Parses a zone file body.
///
/// Only complete lines are used: a body that stops mid-line is a truncated
/// download, and a cut-off `1.2.3.0/2` must not pass as a valid `/2` range.
fn parse_ranges(body: &str) -> Vec<String> {
    let complete = match body.rfind('\n') {
        Some(end) => &body[..=end],
        None => return Vec::new(),
    };
    complete.lines().filter_map(parse_range_line).collect()
}

fn parse_range_line(line: &str) -> Option<String> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let (address, prefix) = line.split_once('/')?;
    let address: Ipv4Addr = address.parse().ok()?;
    let prefix: u8 = prefix.parse().ok()?;
    if prefix > 32 {
        return None;
    }
    Some(format!("{address}/{prefix}"))
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
    use std::sync::atomic::AtomicUsize;
    use std::sync::mpsc;
    use std::time::Instant;

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

    #[test]
    fn ignores_a_cut_off_last_line() {
        // `1.2.3.0/2` is a valid /2 CIDR but the line was cut off, so only the
        // newline-terminated line survives.
        assert_eq!(parse_ranges("10.0.0.0/8\n1.2.3.0/2"), vec!["10.0.0.0/8"]);
        assert!(parse_ranges("10.0.0.0/8").is_empty());
    }

    #[test]
    fn rejects_invalid_range_lines() {
        let body = "10.0.0.0/8\n10.0.0.0/33\nnot-a-cidr\n10.0.0/8\n10.0.0.0\n\n# comment\n192.168.0.0/16\n";
        assert_eq!(parse_ranges(body), vec!["10.0.0.0/8", "192.168.0.0/16"]);
    }

    fn http_listener(response: &'static [u8]) -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        thread::spawn(move || {
            for _ in 0..4 {
                let Ok((mut socket, _)) = listener.accept() else {
                    return;
                };
                let mut reader = BufReader::new(socket.try_clone().unwrap());
                let mut line = String::new();
                while reader
                    .read_line(&mut line)
                    .map(|read| read > 0)
                    .unwrap_or(false)
                {
                    if line == "\r\n" {
                        break;
                    }
                    line.clear();
                }
                let _ = socket.write_all(response);
            }
        });
        address
    }

    fn fetch_test_zone(address: std::net::SocketAddr) -> Result<Vec<String>, String> {
        let (tx, _rx) = mpsc::channel();
        let agent = ureq::AgentBuilder::new().build();
        let url = format!("http://{address}/zone.zone");
        fetch_zone(&agent, &url, "ZZ", &tx)
    }

    #[test]
    fn rejects_a_chunked_download_cut_off_mid_line() {
        // A well-formed chunked response whose last line was cut off: there is
        // no content length, so the missing newline is the only signal.
        let address = http_listener(
            b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\n14\r\n10.0.0.0/8\n1.2.3.0/2\r\n0\r\n\r\n",
        );
        let error = fetch_test_zone(address).unwrap_err();
        assert!(error.contains("download incomplete"), "{error}");
    }

    #[test]
    fn rejects_a_truncated_chunked_body() {
        // The connection closes mid-chunk, without a terminating chunk.
        let address = http_listener(
            b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\n14\r\n10.0.0.0/8\n1.2.3.0/2",
        );
        let error = fetch_test_zone(address).unwrap_err();
        assert!(error.contains("download incomplete"), "{error}");
    }

    #[test]
    fn rejects_a_body_shorter_than_its_content_length() {
        let address = http_listener(
            b"HTTP/1.1 200 OK\r\ncontent-length: 100\r\nconnection: close\r\n\r\n10.0.0.0/8\n192.168.0.0/16\n",
        );
        let error = fetch_test_zone(address).unwrap_err();
        assert!(error.contains("download incomplete"), "{error}");
    }

    #[test]
    fn accepts_a_complete_chunked_download() {
        let address = http_listener(
            b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\n1a\r\n10.0.0.0/8\n192.168.0.0/16\n\r\n0\r\n\r\n",
        );
        let ranges = fetch_test_zone(address).unwrap();
        assert_eq!(ranges, vec!["10.0.0.0/8", "192.168.0.0/16"]);
    }

    #[test]
    fn probe_pool_never_exceeds_its_limit() {
        let pool = WorkerPool::new(4);
        let running = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let (done_tx, done_rx) = mpsc::channel();

        for _ in 0..40 {
            let running = Arc::clone(&running);
            let peak = Arc::clone(&peak);
            let done_tx = done_tx.clone();
            pool.submit(move || {
                let now = running.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(now, Ordering::SeqCst);
                thread::sleep(Duration::from_millis(10));
                running.fetch_sub(1, Ordering::SeqCst);
                let _ = done_tx.send(());
            });
        }

        pool.finish();

        assert_eq!(done_rx.try_iter().count(), 40);
        let peak = peak.load(Ordering::SeqCst);
        assert!(peak > 1, "probes should overlap, peak={peak}");
        assert!(peak <= 4, "peak {peak} exceeds the pool limit");
    }

    #[test]
    fn dropping_the_guard_kills_and_reaps_the_child() {
        let child = match Command::new("sleep").arg("30").spawn() {
            Ok(child) => child,
            // No `sleep` on this platform: nothing to exercise.
            Err(_) => return,
        };
        let started = Instant::now();
        drop(NmapChild::new(child));
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "drop waited for the child instead of killing it"
        );
    }

    #[test]
    fn cancel_kills_the_nmap_child() {
        let child = match Command::new("sleep").arg("30").spawn() {
            Ok(child) => child,
            Err(_) => return,
        };
        let guard = NmapChild::new(child);
        let finished = Arc::new(AtomicBool::new(false));
        watch_cancel(
            guard.handle(),
            Arc::new(AtomicBool::new(true)),
            Arc::clone(&finished),
        );

        assert!(
            guard.wait().is_none(),
            "the cancelled child should already be reaped"
        );
        assert!(!finished.load(Ordering::Relaxed));
    }

    #[test]
    fn done_message_reports_resource_failures() {
        let summary = fast::Summary {
            attempted: 100,
            open: 2,
            elapsed: Duration::from_secs(2),
            cancelled: false,
            limit_reached: false,
            resource_failures: 3,
        };
        let message = fast_done_message(&summary);
        assert!(message.contains("2 open port(s)"), "{message}");
        assert!(
            message.contains("3 probes failed due to resource limits"),
            "{message}"
        );

        let quiet = fast::Summary {
            attempted: 100,
            open: 2,
            elapsed: Duration::from_secs(2),
            cancelled: false,
            limit_reached: false,
            resource_failures: 0,
        };
        assert!(!fast_done_message(&quiet).contains("resource limits"));
    }
}
