use std::collections::HashSet;
use std::io::{self, Write};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::Arc;
use std::thread::JoinHandle;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{
    layout::{Alignment, Constraint, Layout, Position, Rect},
    style::{Color, Modifier, Style},
    text::Span,
    widgets::{
        Block, BorderType, Cell, Clear, List, ListItem, ListState, Paragraph, Row, Table,
        TableState,
    },
    Frame,
};

use crate::mc::{OnlineMode, Status};
use crate::scan::{self, ScanEvent, ScanOptions};

const DEFAULT_PORT: &str = "25565";
const ALL_VERSIONS: &str = "All versions";

#[derive(Clone, Copy, PartialEq, Eq)]
enum Field {
    Target,
    Port,
}

enum Probe {
    Pending,
    Online(Status),
    Offline(String),
}

struct Entry {
    addr: String,
    port: u16,
    probe: Probe,
}

struct VersionPicker {
    items: Vec<String>,
    state: ListState,
}

pub struct App {
    target: String,
    port: String,
    field: Field,
    editing: bool,
    target_before: String,
    port_before: String,
    entries: Vec<Entry>,
    table: TableState,
    version_filter: Option<String>,
    picker: Option<VersionPicker>,
    status: String,
    progress: Option<f32>,
    scanning: bool,
    options: ScanOptions,
    cancel: Arc<AtomicBool>,
    fast_scan: bool,
    scan_thread: Option<JoinHandle<()>>,
    /// Every address/port already listed, so duplicates stay O(1) to drop.
    seen: HashSet<(String, u16)>,
    pub should_quit: bool,
    tx: Sender<ScanEvent>,
    rx: Receiver<ScanEvent>,
}

impl App {
    pub fn new(target: Option<String>, options: ScanOptions) -> Self {
        let (tx, rx) = mpsc::channel();
        Self {
            target: target
                .map(|t| t.trim().to_string())
                .filter(|t| !t.is_empty())
                .unwrap_or_else(|| scan::DEFAULT_TARGET.to_string()),
            port: DEFAULT_PORT.to_string(),
            field: Field::Target,
            editing: false,
            target_before: String::new(),
            port_before: String::new(),
            entries: Vec::new(),
            table: TableState::default(),
            version_filter: None,
            picker: None,
            status: "Ready — press s to scan".to_string(),
            progress: None,
            scanning: false,
            options,
            cancel: Arc::new(AtomicBool::new(false)),
            fast_scan: false,
            scan_thread: None,
            seen: HashSet::new(),
            should_quit: false,
            tx,
            rx,
        }
    }

    pub fn drain_events(&mut self) {
        while let Ok(event) = self.rx.try_recv() {
            match event {
                ScanEvent::Host { addr, port } => {
                    if !self.seen.insert((addr.clone(), port)) {
                        continue;
                    }
                    let candidate = Entry {
                        addr,
                        port,
                        probe: Probe::Pending,
                    };
                    // Insert in sorted position instead of re-sorting the
                    // whole list for every hit.
                    let position = self
                        .entries
                        .partition_point(|entry| entry_order(entry, &candidate).is_lt());
                    self.entries.insert(position, candidate);
                    // Rows only shift while no version filter hides any of them.
                    if self.version_filter.is_none() {
                        if let Some(selected) = self.table.selected() {
                            if position <= selected {
                                self.table.select(Some(selected + 1));
                            }
                        }
                    }
                }
                ScanEvent::Server { addr, port, result } => {
                    if let Some(entry) = self
                        .entries
                        .iter_mut()
                        .find(|entry| entry.addr == addr && entry.port == port)
                    {
                        entry.probe = match result {
                            Ok(status) => Probe::Online(status),
                            Err(reason) => Probe::Offline(reason),
                        };
                    }
                }
                ScanEvent::Progress(percent) => {
                    self.progress = Some(percent);
                }
                ScanEvent::Info(message) => {
                    self.status = message;
                }
                ScanEvent::Done(message) => {
                    self.scanning = false;
                    self.fast_scan = false;
                    self.progress = None;
                    self.status = message;
                }
                ScanEvent::Failed(message) => {
                    self.scanning = false;
                    self.fast_scan = false;
                    self.progress = None;
                    self.status = format!("Error: {message}");
                }
            }
        }
        self.ensure_selection();
    }

    pub fn handle_key(&mut self, key: KeyEvent) {
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            self.should_quit = true;
            return;
        }

        if self.picker.is_some() {
            self.handle_picker_key(key);
            return;
        }

        if self.editing {
            self.handle_edit_key(key);
            return;
        }

        match key.code {
            KeyCode::Char('q') => self.should_quit = true,
            KeyCode::Char('s') => self.start_scan(),
            KeyCode::Char('i') | KeyCode::Char('/') | KeyCode::Enter => self.begin_edit(),
            KeyCode::Char('v') => self.open_version_picker(),
            KeyCode::Char('p') => self.ping_selected(),
            KeyCode::Char('x') => self.stop_scan(),
            KeyCode::Char('c') => self.copy_selected(),
            KeyCode::Char('C') => self.clear_results(),
            KeyCode::Down | KeyCode::Char('j') => self.select_offset(1),
            KeyCode::Up | KeyCode::Char('k') => self.select_offset(-1),
            KeyCode::PageDown => self.select_offset(10),
            KeyCode::PageUp => self.select_offset(-10),
            KeyCode::Home => self.select_index(0),
            KeyCode::End => self.select_index(usize::MAX),
            _ => {}
        }
    }

    fn handle_edit_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc => {
                self.target = self.target_before.clone();
                self.port = self.port_before.clone();
                self.editing = false;
                self.status = "Edit cancelled".to_string();
            }
            KeyCode::Enter => {
                self.editing = false;
                self.status = "Target set — press s to scan".to_string();
            }
            KeyCode::Tab | KeyCode::BackTab => {
                self.field = match self.field {
                    Field::Target => Field::Port,
                    Field::Port => Field::Target,
                };
            }
            KeyCode::Backspace => match self.field {
                Field::Target => {
                    self.target.pop();
                }
                Field::Port => {
                    self.port.pop();
                }
            },
            KeyCode::Char(c) if !c.is_control() => {
                let (value, max_len) = match self.field {
                    Field::Target => (&mut self.target, 96),
                    Field::Port => (&mut self.port, 5),
                };
                if value.chars().count() < max_len {
                    value.push(c);
                }
            }
            _ => {}
        }
    }

    fn begin_edit(&mut self) {
        self.target_before = self.target.clone();
        self.port_before = self.port.clone();
        self.field = Field::Target;
        self.editing = true;
        self.status = "Editing — Tab switches field, Enter applies, Esc cancels".to_string();
    }

    fn start_scan(&mut self) {
        if self.scanning {
            self.status = "A scan is already running".to_string();
            return;
        }

        let target = self.target.trim().to_string();
        if target.is_empty() {
            self.status = "Enter a target first (press i)".to_string();
            return;
        }
        if target.starts_with('-') {
            self.status = "Target must not start with '-'".to_string();
            return;
        }

        let port: u16 = match self.port.trim().parse() {
            Ok(port) if port > 0 => port,
            _ => {
                self.status = "Port must be between 1 and 65535".to_string();
                return;
            }
        };

        self.entries.clear();
        self.seen.clear();
        self.table.select(None);
        self.scanning = true;
        self.progress = None;
        self.cancel.store(false, Ordering::Relaxed);
        self.fast_scan = !self.options.nmap && scan::supports_fast(&target);
        self.status = if self.fast_scan {
            match scan::country_code(&target) {
                Some(code) => format!("Loading IPv4 ranges for {code}…"),
                None => format!("Starting fast scan of {target} on TCP {port}…"),
            }
        } else {
            format!("Starting nmap scan of {target} on TCP {port}…")
        };
        self.scan_thread = Some(scan::spawn_scan(
            target,
            port,
            self.options.clone(),
            self.tx.clone(),
            self.cancel.clone(),
        ));
    }

    fn ping_selected(&mut self) {
        let Some(index) = self.selected_entry_index() else {
            return;
        };
        let Some(entry) = self.entries.get_mut(index) else {
            return;
        };

        entry.probe = Probe::Pending;
        let addr = entry.addr.clone();
        let port = entry.port;
        self.status = format!("Pinging {addr}:{port}…");
        scan::spawn_probe(addr, port, self.tx.clone());
    }

    fn open_version_picker(&mut self) {
        let items = self.version_choices();
        let selected = self
            .version_filter
            .as_ref()
            .and_then(|filter| {
                items
                    .iter()
                    .position(|item| item.eq_ignore_ascii_case(filter))
            })
            .unwrap_or(0);
        let mut state = ListState::default();
        state.select(Some(selected));
        self.picker = Some(VersionPicker { items, state });
        self.status =
            "Choose a Minecraft version — ↑/↓, Enter apply, Esc cancel".to_string();
    }

    fn handle_picker_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc | KeyCode::Char('v') => {
                self.picker = None;
                self.status = "Version selection cancelled".to_string();
            }
            KeyCode::Enter => {
                let choice = self
                    .picker
                    .as_ref()
                    .and_then(|picker| {
                        picker
                            .items
                            .get(picker.state.selected().unwrap_or(0))
                            .cloned()
                    })
                    .unwrap_or_else(|| ALL_VERSIONS.to_string());
                self.picker = None;
                self.apply_version_filter(choice);
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if let Some(picker) = self.picker.as_mut() {
                    let count = picker.items.len();
                    if count > 0 {
                        let next = (picker.state.selected().unwrap_or(0) + 1).min(count - 1);
                        picker.state.select(Some(next));
                    }
                }
            }
            KeyCode::Up | KeyCode::Char('k') => {
                if let Some(picker) = self.picker.as_mut() {
                    let next = picker.state.selected().unwrap_or(0).saturating_sub(1);
                    picker.state.select(Some(next));
                }
            }
            KeyCode::Home => {
                if let Some(picker) = self.picker.as_mut() {
                    picker.state.select(Some(0));
                }
            }
            KeyCode::End => {
                if let Some(picker) = self.picker.as_mut() {
                    if !picker.items.is_empty() {
                        picker.state.select(Some(picker.items.len() - 1));
                    }
                }
            }
            _ => {}
        }
    }

    fn apply_version_filter(&mut self, choice: String) {
        self.version_filter = if choice == ALL_VERSIONS {
            None
        } else {
            Some(choice)
        };
        self.ensure_selection();
        let status = match &self.version_filter {
            Some(filter) => format!(
                "Version filter: {filter} — {} matching server(s)",
                self.visible_indices().len()
            ),
            None => "Showing all versions".to_string(),
        };
        self.status = status;
    }

    fn version_choices(&self) -> Vec<String> {
        let mut versions: Vec<String> = self
            .entries
            .iter()
            .filter_map(|entry| match &entry.probe {
                Probe::Online(status) => Some(status.version.clone()),
                _ => None,
            })
            .collect();
        versions.sort_by_key(|version| version.to_ascii_lowercase());
        versions.dedup_by(|left, right| left.eq_ignore_ascii_case(right));

        if let Some(filter) = &self.version_filter {
            if !versions
                .iter()
                .any(|version| version.eq_ignore_ascii_case(filter))
            {
                versions.push(filter.clone());
                versions.sort_by_key(|version| version.to_ascii_lowercase());
            }
        }

        versions.insert(0, ALL_VERSIONS.to_string());
        versions
    }

    fn matches_filter(&self, entry: &Entry) -> bool {
        match &self.version_filter {
            None => true,
            Some(filter) => match &entry.probe {
                Probe::Online(status) => version_matches(&status.version, filter),
                _ => false,
            },
        }
    }

    fn visible_indices(&self) -> Vec<usize> {
        self.entries
            .iter()
            .enumerate()
            .filter(|(_, entry)| self.matches_filter(entry))
            .map(|(index, _)| index)
            .collect()
    }

    fn ensure_selection(&mut self) {
        let visible = self.visible_indices().len();
        if visible == 0 {
            self.table.select(None);
        } else {
            match self.table.selected() {
                Some(index) if index < visible => {}
                _ => self.table.select(Some(0)),
            }
        }
    }

    fn selected_entry_index(&self) -> Option<usize> {
        self.table
            .selected()
            .and_then(|index| self.visible_indices().get(index).copied())
    }

    fn stop_scan(&mut self) {
        if !self.scanning {
            return;
        }
        self.cancel.store(true, Ordering::Relaxed);
        self.status = if self.fast_scan {
            "Stopping fast scan…".to_string()
        } else {
            "Stopping nmap scan…".to_string()
        };
    }

    fn copy_selected(&mut self) {
        let Some(addr) = self
            .selected_entry_index()
            .and_then(|index| self.entries.get(index))
            .map(|entry| entry.addr.clone())
        else {
            self.status = "Nothing selected to copy".to_string();
            return;
        };

        self.status = match write_clipboard(&addr) {
            Ok(()) => format!("Copied {addr} to clipboard"),
            Err(error) => format!("Error: could not copy {addr}: {error}"),
        };
    }

    fn clear_results(&mut self) {
        if self.scanning {
            self.status = "Cannot clear results while scanning".to_string();
            return;
        }
        self.entries.clear();
        self.seen.clear();
        self.table.select(None);
        self.version_filter = None;
        self.picker = None;
        self.progress = None;
        self.status = "Cleared results".to_string();
    }

    fn select_offset(&mut self, delta: isize) {
        let Some(current) = self.table.selected() else {
            return;
        };
        let visible = self.visible_indices().len();
        if visible == 0 {
            return;
        }
        let last = visible - 1;
        let next = (current as isize + delta).clamp(0, last as isize) as usize;
        self.table.select(Some(next));
    }

    fn select_index(&mut self, index: usize) {
        let visible = self.visible_indices().len();
        if visible == 0 {
            self.table.select(None);
        } else {
            self.table.select(Some(index.min(visible - 1)));
        }
    }

    pub fn draw(&mut self, frame: &mut Frame) {
        self.ensure_selection();
        let chunks = Layout::vertical([
            Constraint::Length(3),
            Constraint::Min(3),
            Constraint::Length(1),
            Constraint::Length(1),
        ])
        .split(frame.area());

        self.draw_config(frame, chunks[0]);
        self.draw_table(frame, chunks[1]);
        self.draw_status(frame, chunks[2]);
        self.draw_footer(frame, chunks[3]);
        self.draw_picker(frame);
    }

    fn draw_config(&mut self, frame: &mut Frame, area: Rect) {
        let columns = Layout::horizontal([Constraint::Min(24), Constraint::Length(16)]).split(area);
        let editing_target = self.editing && self.field == Field::Target;
        let editing_port = self.editing && self.field == Field::Port;

        let target_block = Block::bordered()
            .border_type(BorderType::Rounded)
            .title(" Target / country (DE, US) ")
            .border_style(focus_style(editing_target));
        let target_inner = target_block.inner(columns[0]);
        frame.render_widget(target_block, columns[0]);

        let (visible, cursor) = visible_tail(&self.target, target_inner.width);
        frame.render_widget(
            Paragraph::new(visible).style(Style::new().fg(Color::White)),
            target_inner,
        );
        if editing_target && target_inner.width > 0 {
            frame.set_cursor_position(Position::new(target_inner.x + cursor, target_inner.y));
        }

        let port_block = Block::bordered()
            .border_type(BorderType::Rounded)
            .title(" Port ")
            .border_style(focus_style(editing_port));
        let port_inner = port_block.inner(columns[1]);
        frame.render_widget(port_block, columns[1]);

        let (visible, cursor) = visible_tail(&self.port, port_inner.width);
        frame.render_widget(
            Paragraph::new(visible).style(Style::new().fg(Color::White)),
            port_inner,
        );
        if editing_port && port_inner.width > 0 {
            frame.set_cursor_position(Position::new(port_inner.x + cursor, port_inner.y));
        }
    }

    fn draw_table(&mut self, frame: &mut Frame, area: Rect) {
        let total = self.entries.len();
        let visible = self.visible_indices();
        let shown = visible.len();
        let online = self
            .entries
            .iter()
            .filter(|entry| matches!(entry.probe, Probe::Online(_)))
            .count();
        let title = match &self.version_filter {
            Some(filter) => format!(" Servers — {shown}/{total} on version {filter} "),
            None => format!(" Servers — {total} open, {online} Minecraft "),
        };

        let header = Row::new(["IP", "Status", "Mode", "Version", "Players", "MOTD"])
            .style(Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD));

        let rows: Vec<Row> = visible
            .iter()
            .map(|&index| {
                let entry = &self.entries[index];
                match &entry.probe {
                Probe::Pending => Row::new(vec![
                    Cell::from(entry.addr.clone()),
                    Cell::from(Span::styled(
                        "pinging…",
                        Style::new().fg(Color::Yellow),
                    )),
                    Cell::from(Span::styled("?", Style::new().fg(Color::DarkGray))),
                    Cell::from("—"),
                    Cell::from("—"),
                    Cell::from(Span::styled(
                        "checking server list ping",
                        Style::new().fg(Color::DarkGray),
                    )),
                ]),
                Probe::Online(status) => Row::new(vec![
                    Cell::from(entry.addr.clone()),
                    Cell::from(Span::styled(
                        "online",
                        Style::new()
                            .fg(Color::Green)
                            .add_modifier(Modifier::BOLD),
                    )),
                    Cell::from(mode_span(status.online_mode)),
                    Cell::from(status.version.clone()),
                    Cell::from(format!("{}/{}", status.online, status.max)),
                    Cell::from(Span::styled(
                        format!("{} ({} ms)", status.motd, status.latency_ms),
                        Style::new().fg(Color::Gray),
                    )),
                ]),
                Probe::Offline(reason) => Row::new(vec![
                    Cell::from(entry.addr.clone()),
                    Cell::from(Span::styled("not MC", Style::new().fg(Color::Red))),
                    Cell::from("—"),
                    Cell::from("—"),
                    Cell::from("—"),
                    Cell::from(Span::styled(
                        reason.clone(),
                        Style::new().fg(Color::DarkGray),
                    )),
                ]),
                }
            })
            .collect();

        let widths = [
            Constraint::Length(15),
            Constraint::Length(9),
            Constraint::Length(12),
            Constraint::Length(20),
            Constraint::Length(9),
            Constraint::Min(12),
        ];

        let block = Block::bordered()
            .border_type(BorderType::Rounded)
            .title(title);
        let inner = block.inner(area);
        let table = Table::new(rows, widths)
            .header(header)
            .block(block)
            .column_spacing(1)
            .row_highlight_style(Style::new().bg(Color::DarkGray));
        frame.render_stateful_widget(table, area, &mut self.table);

        if shown == 0 {
            let message = match &self.version_filter {
                Some(filter) if total > 0 => {
                    format!("No servers on version {filter} — press v to change")
                }
                _ => "No servers yet — press s to scan".to_string(),
            };
            frame.render_widget(
                Paragraph::new(message)
                    .alignment(Alignment::Center)
                    .style(Style::new().fg(Color::DarkGray)),
                inner,
            );
        }
    }

    fn draw_status(&mut self, frame: &mut Frame, area: Rect) {
        let style = if self.scanning {
            Style::new().fg(Color::Yellow)
        } else if self.status.starts_with("Error") {
            Style::new().fg(Color::Red)
        } else {
            Style::new().fg(Color::Gray)
        };

        let mut text = self.status.clone();
        if let Some(percent) = self.progress {
            text.push_str(&format!("  ({percent:.0}% checked)"));
        }

        frame.render_widget(Paragraph::new(format!(" {text}")).style(style), area);
    }

    fn draw_footer(&mut self, frame: &mut Frame, area: Rect) {
        let keys = " s scan  i edit  x stop  v version  p ping  c copy  C clear  ↑↓ select  q quit";
        frame.render_widget(
            Paragraph::new(keys).style(Style::new().fg(Color::DarkGray)),
            area,
        );
    }

    fn draw_picker(&mut self, frame: &mut Frame) {
        let Some(picker) = self.picker.as_mut() else {
            return;
        };

        let longest = picker
            .items
            .iter()
            .map(|item| item.chars().count())
            .max()
            .unwrap_or(20) as u16;
        let width = (longest + 8).clamp(30, 60).min(frame.area().width);
        let height = (picker.items.len() as u16 + 2)
            .clamp(3, 16)
            .min(frame.area().height);
        let area = centered_rect(width, height, frame.area());
        if area.width == 0 || area.height == 0 {
            return;
        }

        let items: Vec<ListItem> = picker
            .items
            .iter()
            .map(|item| ListItem::new(item.clone()))
            .collect();
        let list = List::new(items)
            .block(
                Block::bordered()
                    .border_type(BorderType::Rounded)
                    .title(" Minecraft version "),
            )
            .highlight_style(Style::new().bg(Color::DarkGray).fg(Color::White))
            .highlight_symbol("› ");

        frame.render_widget(Clear, area);
        frame.render_stateful_widget(list, area, &mut picker.state);
    }
}

/// Copies `text` through the terminal with OSC 52, so no system clipboard
/// library is needed and it also works over SSH. Terminals without OSC 52
/// support ignore the sequence.
fn write_clipboard(text: &str) -> io::Result<()> {
    let tmux = std::env::var_os("TMUX").is_some();
    let mut stdout = io::stdout();
    stdout.write_all(osc52_sequence(text, tmux).as_bytes())?;
    stdout.flush()
}

fn osc52_sequence(text: &str, tmux: bool) -> String {
    let payload = base64(text.as_bytes());
    if tmux {
        // tmux drops unrecognised sequences unless they arrive as passthrough.
        format!("\x1bPtmux;\x1b\x1b]52;c;{payload}\x07\x1b\\")
    } else {
        format!("\x1b]52;c;{payload}\x07")
    }
}

const BASE64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        out.push(BASE64[(b0 >> 2) as usize] as char);
        out.push(BASE64[(((b0 & 0b11) << 4) | (b1 >> 4)) as usize] as char);
        out.push(if chunk.len() > 1 {
            BASE64[(((b1 & 0b1111) << 2) | (b2 >> 6)) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            BASE64[(b2 & 0b111111) as usize] as char
        } else {
            '='
        });
    }
    out
}

/// Table order: numeric IPv4 first, then anything else by text, then by port.
fn entry_order(left: &Entry, right: &Entry) -> std::cmp::Ordering {
    let by_addr = match (left.addr.parse::<IpAddr>(), right.addr.parse::<IpAddr>()) {
        (Ok(left), Ok(right)) => left.cmp(&right),
        _ => left.addr.cmp(&right.addr),
    };
    by_addr.then(left.port.cmp(&right.port))
}

impl Drop for App {
    fn drop(&mut self) {
        // Stop the running scan; the nmap path kills and waits on its child, so
        // wait for it rather than leaving nmap running after the UI is gone.
        self.cancel.store(true, Ordering::Relaxed);
        let joins = !self.fast_scan;
        if let Some(handle) = self.scan_thread.take() {
            if joins {
                let _ = handle.join();
            }
        }
    }
}

fn focus_style(focused: bool) -> Style {
    if focused {
        Style::new().fg(Color::Yellow)
    } else {
        Style::new().fg(Color::DarkGray)
    }
}

/// "offline mode" is highlighted: cracked clients can join those servers.
fn mode_span(mode: OnlineMode) -> Span<'static> {
    match mode {
        OnlineMode::Online => Span::styled("online mode", Style::new().fg(Color::Green)),
        OnlineMode::Offline => Span::styled(
            "offline mode",
            Style::new().fg(Color::Yellow).add_modifier(Modifier::BOLD),
        ),
        OnlineMode::Unknown => Span::styled("?", Style::new().fg(Color::DarkGray)),
    }
}

fn version_matches(server_version: &str, filter: &str) -> bool {
    server_version.eq_ignore_ascii_case(filter)
        || server_version
            .to_ascii_lowercase()
            .contains(&filter.to_ascii_lowercase())
}

fn centered_rect(width: u16, height: u16, area: Rect) -> Rect {
    let width = width.min(area.width);
    let height = height.min(area.height);
    Rect {
        x: area.x + (area.width - width) / 2,
        y: area.y + (area.height - height) / 2,
        width,
        height,
    }
}

/// Returns the part of `value` that fits in `width` plus the cursor column.
fn visible_tail(value: &str, width: u16) -> (String, u16) {
    let width = width as usize;
    if width == 0 {
        return (String::new(), 0);
    }
    let len = value.chars().count();
    if len < width {
        (value.to_string(), len as u16)
    } else {
        (
            value.chars().skip(len - width + 1).collect(),
            (width - 1) as u16,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mc::Status;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    fn status(version: &str) -> Status {
        Status {
            version: version.to_string(),
            online: 1,
            max: 10,
            motd: "test".to_string(),
            latency_ms: 1,
            online_mode: OnlineMode::Online,
        }
    }

    fn entry(addr: &str, version: Option<&str>) -> Entry {
        Entry {
            addr: addr.to_string(),
            port: 25565,
            probe: version
                .map(|version| Probe::Online(status(version)))
                .unwrap_or(Probe::Pending),
        }
    }

    fn app_with(entries: Vec<Entry>) -> App {
        let mut app = App::new(Some("127.0.0.1".to_string()), ScanOptions::default());
        app.entries = entries;
        app
    }

    fn push(app: &mut App, event: ScanEvent) {
        app.tx.send(event).unwrap();
        app.drain_events();
    }

    #[test]
    fn host_events_are_deduplicated_and_inserted_in_order() {
        let mut app = app_with(Vec::new());
        for addr in ["10.0.0.5", "10.0.0.2", "10.0.0.9", "10.0.0.5"] {
            push(
                &mut app,
                ScanEvent::Host {
                    addr: addr.to_string(),
                    port: 25565,
                },
            );
        }

        let addrs: Vec<&str> = app.entries.iter().map(|entry| entry.addr.as_str()).collect();
        assert_eq!(addrs, ["10.0.0.2", "10.0.0.5", "10.0.0.9"]);
    }

    #[test]
    fn server_events_match_on_address_and_port() {
        let mut app = app_with(Vec::new());
        for port in [25565u16, 25566] {
            push(
                &mut app,
                ScanEvent::Host {
                    addr: "10.0.0.1".to_string(),
                    port,
                },
            );
        }

        push(
            &mut app,
            ScanEvent::Server {
                addr: "10.0.0.1".to_string(),
                port: 25566,
                result: Ok(status("1.21.4")),
            },
        );

        assert!(matches!(app.entries[0].probe, Probe::Pending));
        assert!(matches!(app.entries[1].probe, Probe::Online(_)));
    }

    #[test]
    fn version_filter_matches_exact_and_prefixed_versions() {
        assert!(version_matches("1.20.4", "1.20.4"));
        assert!(version_matches("Paper 1.20.4", "1.20.4"));
        assert!(version_matches("1.21.4", "1.21"));
        assert!(!version_matches("1.20.4", "1.19"));
    }

    #[test]
    fn version_choices_are_sorted_and_unique() {
        let app = app_with(vec![
            entry("10.0.0.1", Some("1.21.4")),
            entry("10.0.0.2", Some("1.20.4")),
            entry("10.0.0.3", Some("1.21.4")),
            entry("10.0.0.4", None),
        ]);
        assert_eq!(
            app.version_choices().join(","),
            "All versions,1.20.4,1.21.4"
        );
    }

    #[test]
    fn base64_matches_rfc4648_vectors() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn osc52_sequence_wraps_ips_and_tmux_passthrough() {
        assert_eq!(
            osc52_sequence("10.0.0.1", false),
            "\x1b]52;c;MTAuMC4wLjE=\x07"
        );
        assert_eq!(
            osc52_sequence("10.0.0.1", true),
            "\x1bPtmux;\x1b\x1b]52;c;MTAuMC4wLjE=\x07\x1b\\"
        );
    }

    #[test]
    fn clear_shortcut_is_uppercase_c() {
        let mut app = app_with(vec![entry("10.0.0.1", None)]);
        app.handle_key(KeyEvent::new(KeyCode::Char('C'), KeyModifiers::SHIFT));
        assert!(app.entries.is_empty());
        assert_eq!(app.status, "Cleared results");
    }

    #[test]
    fn picker_applies_version_filter() {
        let mut app = app_with(vec![
            entry("10.0.0.1", Some("1.21.4")),
            entry("10.0.0.2", Some("1.20.4")),
            entry("10.0.0.3", None),
        ]);

        app.handle_key(KeyEvent::new(KeyCode::Char('v'), KeyModifiers::NONE));
        assert!(app.picker.is_some());

        app.handle_key(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE));
        app.handle_key(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE));
        app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));

        assert_eq!(app.version_filter.as_deref(), Some("1.21.4"));
        assert_eq!(app.visible_indices(), vec![0]);
        assert_eq!(app.table.selected(), Some(0));
    }
}
