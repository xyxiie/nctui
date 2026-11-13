//! Direct high-concurrency TCP connect scanner for IPv4 ranges.
//!
//! Unlike nmap, this skips host discovery and probes every address directly,
//! orders targets randomly, and keeps thousands of connections in flight.

use std::fs;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use crate::scan::{probe_thread, with_commas, ScanEvent, ScanOptions};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Range {
    base: u32,
    bits: u32,
}

impl Range {
    /// Accepts `a.b.c.d/prefix` or a single IPv4 address (`/32`).
    pub fn parse(text: &str) -> Option<Self> {
        let text = text.trim();
        if let Some((address, prefix)) = text.split_once('/') {
            let address: Ipv4Addr = address.parse().ok()?;
            let prefix: u32 = prefix.parse().ok()?;
            if prefix > 32 {
                return None;
            }
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            Some(Self {
                base: u32::from(address) & mask,
                bits: 32 - prefix,
            })
        } else {
            let address: Ipv4Addr = text.parse().ok()?;
            Some(Self {
                base: u32::from(address),
                bits: 0,
            })
        }
    }

    pub fn size(self) -> u64 {
        1u64 << self.bits
    }
}

struct Rng(u64);

impl Rng {
    fn new() -> Self {
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos() as u64)
            .unwrap_or(0x9E37_79B9_7F4A_7C15)
            ^ (std::process::id() as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15);
        Self(seed)
    }

    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut value = self.0;
        value = (value ^ (value >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        value ^ (value >> 31)
    }
}

/// Walks every offset in a power-of-two range exactly once, in random order.
struct OffsetWalker {
    mask: u64,
    offset: u64,
    multiplier: u64,
    increment: u64,
    remaining: u64,
}

impl OffsetWalker {
    fn new(size: u64, rng: &mut Rng) -> Self {
        let mask = size - 1;
        let offset = if size == 1 { 0 } else { rng.next_u64() & mask };
        // Odd increment and a multiplier of 1 mod 4 give a full-period LCG.
        let multiplier = ((rng.next_u64() & mask) | 1) & !2;
        let increment = (rng.next_u64() & mask) | 1;
        Self {
            mask,
            offset,
            multiplier,
            increment,
            remaining: size,
        }
    }

    fn next_offset(&mut self) -> Option<u64> {
        if self.remaining == 0 {
            return None;
        }
        let offset = self.offset;
        self.offset = self
            .offset
            .wrapping_mul(self.multiplier)
            .wrapping_add(self.increment)
            & self.mask;
        self.remaining -= 1;
        Some(offset)
    }
}

#[derive(Debug)]
pub struct Summary {
    pub attempted: u64,
    pub open: usize,
    pub elapsed: Duration,
    pub cancelled: bool,
    pub limit_reached: bool,
}

pub fn scan(
    ranges: Vec<Range>,
    port: u16,
    options: &ScanOptions,
    tx: Sender<ScanEvent>,
    cancel: Arc<AtomicBool>,
) -> Result<Summary, String> {
    let workers = std::thread::available_parallelism()
        .map(|count| count.get().min(4))
        .unwrap_or(2);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .enable_all()
        .build()
        .map_err(|error| format!("could not start scan runtime: {error}"))?;
    runtime.block_on(scan_async(ranges, port, options, tx, cancel))
}

pub fn effective_concurrency(options: &ScanOptions) -> usize {
    let fd_limit = fs::read_to_string("/proc/self/limits")
        .ok()
        .and_then(|text| {
            text.lines()
                .find(|line| line.starts_with("Max open files"))
                .and_then(|line| line.split_whitespace().nth(3))
                .and_then(|value| value.parse::<usize>().ok())
        })
        .unwrap_or(1024);

    let port_count = fs::read_to_string("/proc/sys/net/ipv4/ip_local_port_range")
        .ok()
        .and_then(|text| {
            let mut parts = text.split_whitespace();
            let low = parts.next()?.parse::<u32>().ok()?;
            let high = parts.next()?.parse::<u32>().ok()?;
            Some((high.saturating_sub(low) + 1) as usize)
        })
        .unwrap_or(28_000);

    let cap = fd_limit
        .saturating_sub(128)
        .max(16)
        .min(port_count.saturating_mul(3) / 4)
        .max(16);

    if options.concurrency > 0 {
        options.concurrency.clamp(1, cap)
    } else {
        cap
    }
}

async fn scan_async(
    mut ranges: Vec<Range>,
    port: u16,
    options: &ScanOptions,
    tx: Sender<ScanEvent>,
    cancel: Arc<AtomicBool>,
) -> Result<Summary, String> {
    let started = Instant::now();
    let total: u64 = ranges.iter().map(|range| range.size()).sum();
    let sample = options.sample_percent.clamp(1, 100);
    let concurrency = effective_concurrency(options);
    let sample_suffix = if sample < 100 {
        format!(", {sample}% sample")
    } else {
        String::new()
    };
    let _ = tx.send(ScanEvent::Info(format!(
        "Fast scan: {} address(es) on TCP {port} — {} concurrent, {} ms timeout{}",
        with_commas(total),
        with_commas(concurrency as u64),
        options.timeout.as_millis(),
        sample_suffix
    )));

    let mut rng = Rng::new();
    shuffle(&mut ranges, &mut rng);

    let semaphore = Arc::new(Semaphore::new(concurrency));
    let stop = Arc::new(AtomicBool::new(false));
    let opened = Arc::new(AtomicUsize::new(0));
    let probes = Arc::new(Mutex::new(Vec::new()));
    let mut tasks = JoinSet::new();
    let mut examined = 0u64;
    let mut attempted = 0u64;
    let mut stopped_by_user = false;
    let mut last_progress = Instant::now();
    let sample_all = sample >= 100 || total <= 1024;

    'ranges: for range in &ranges {
        let mut walker = OffsetWalker::new(range.size(), &mut rng);
        while let Some(offset) = walker.next_offset() {
            if cancel.load(Ordering::Relaxed) {
                stopped_by_user = true;
                break 'ranges;
            }
            if stop.load(Ordering::Relaxed) {
                break 'ranges;
            }

            let ip = Ipv4Addr::from(range.base.wrapping_add(offset as u32));
            examined += 1;

            if sample_all || rng.next_u64() % 100 < sample as u64 {
                let permit = match semaphore.clone().acquire_owned().await {
                    Ok(permit) => permit,
                    Err(_) => break 'ranges,
                };
                if cancel.load(Ordering::Relaxed) {
                    stopped_by_user = true;
                    break 'ranges;
                }
                if stop.load(Ordering::Relaxed) {
                    break 'ranges;
                }
                attempted += 1;

                let task_tx = tx.clone();
                let task_opened = opened.clone();
                let task_stop = stop.clone();
                let task_probes = probes.clone();
                let timeout = options.timeout;
                let stop_after = options.stop_after;

                tasks.spawn(async move {
                    let connected = tokio::time::timeout(
                        timeout,
                        TcpStream::connect(SocketAddrV4::new(ip, port)),
                    )
                    .await
                    .map(|result| result.is_ok())
                    .unwrap_or(false);

                    if connected {
                        let count = task_opened.fetch_add(1, Ordering::Relaxed) + 1;
                        let address = ip.to_string();
                        let _ = task_tx.send(ScanEvent::Host {
                            addr: address.clone(),
                            port,
                        });
                        let handle = probe_thread(address, port, task_tx.clone());
                        if let Ok(mut list) = task_probes.lock() {
                            list.push(handle);
                        }
                        if stop_after > 0 && count >= stop_after {
                            task_stop.store(true, Ordering::Relaxed);
                        }
                    }
                    drop(permit);
                });

                while tasks.try_join_next().is_some() {}
            }

            if last_progress.elapsed() >= Duration::from_millis(200) && total > 0 {
                let percent = (examined as f64 / total as f64 * 100.0).min(100.0) as f32;
                let _ = tx.send(ScanEvent::Progress(percent));
                last_progress = Instant::now();
            }
        }
    }

    while tasks.join_next().await.is_some() {}
    let probe_handles = probes
        .lock()
        .map(|mut list| std::mem::take(&mut *list))
        .unwrap_or_default();
    for handle in probe_handles {
        let _ = handle.join();
    }

    let open = opened.load(Ordering::Relaxed);
    let cancelled = stopped_by_user || cancel.load(Ordering::Relaxed);
    let _ = tx.send(ScanEvent::Progress(100.0));

    Ok(Summary {
        attempted,
        open,
        elapsed: started.elapsed(),
        cancelled,
        limit_reached: options.stop_after > 0 && open >= options.stop_after,
    })
}

fn shuffle(ranges: &mut [Range], rng: &mut Rng) {
    for index in (1..ranges.len()).rev() {
        let swap = (rng.next_u64() % (index as u64 + 1)) as usize;
        ranges.swap(index, swap);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn parses_cidrs_and_single_addresses() {
        let range = Range::parse("192.168.1.77/24").unwrap();
        assert_eq!(range.base, u32::from(Ipv4Addr::new(192, 168, 1, 0)));
        assert_eq!(range.size(), 256);

        let single = Range::parse("10.1.2.3").unwrap();
        assert_eq!(single.base, u32::from(Ipv4Addr::new(10, 1, 2, 3)));
        assert_eq!(single.size(), 1);

        assert!(Range::parse("example.com").is_none());
        assert!(Range::parse("10.0.0.0/33").is_none());
    }

    #[test]
    fn random_walk_covers_every_offset_once() {
        let mut rng = Rng::new();
        for bits in [0u32, 1, 2, 8, 12] {
            let size = 1u64 << bits;
            let mut walker = OffsetWalker::new(size, &mut rng);
            let mut seen = HashSet::new();
            for _ in 0..size {
                seen.insert(walker.next_offset().unwrap());
            }
            assert_eq!(seen.len() as u64, size, "bits={bits}");
            assert!(walker.next_offset().is_none());
        }
    }

    #[test]
    #[ignore = "scans the reserved 198.18.0.0/20 benchmark range"]
    fn benchmark_filtered() {
        let ranges = vec![Range::parse("198.18.0.0/20").unwrap()];
        let options = ScanOptions {
            timeout: Duration::from_millis(300),
            ..ScanOptions::default()
        };
        let (tx, _rx) = std::sync::mpsc::channel();
        let summary = scan(ranges, 9, &options, tx, Arc::new(AtomicBool::new(false))).unwrap();
        let seconds = summary.elapsed.as_secs_f64();
        eprintln!(
            "fast scanner (filtered): {} attempts in {:.2}s = {:.0} addresses/s",
            summary.attempted,
            seconds,
            summary.attempted as f64 / seconds
        );
    }

    #[test]
    #[ignore = "scans 127.0.0.0/18 on loopback"]
    fn benchmark_loopback() {
        let ranges = vec![Range::parse("127.0.0.0/18").unwrap()];
        let options = ScanOptions {
            concurrency: 0,
            timeout: Duration::from_millis(200),
            ..ScanOptions::default()
        };
        let (tx, _rx) = std::sync::mpsc::channel();
        let summary = scan(ranges, 9, &options, tx, Arc::new(AtomicBool::new(false))).unwrap();
        let seconds = summary.elapsed.as_secs_f64();
        eprintln!(
            "fast scanner: {} attempts in {:.2}s = {:.0} addresses/s (open: {})",
            summary.attempted,
            seconds,
            summary.attempted as f64 / seconds,
            summary.open
        );
    }
}
