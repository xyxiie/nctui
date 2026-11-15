mod app;
mod fast;
mod mc;
mod scan;

use std::io;
use std::time::Duration;

use app::App;
use crossterm::{
    event::{self, Event, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};
use scan::{ScanOptions, DEFAULT_TARGET};

fn main() -> io::Result<()> {
    let (initial_target, options) = match parse_args() {
        Ok(parsed) => parsed,
        Err(message) => {
            eprintln!("{message}\n");
            print_help();
            std::process::exit(2);
        }
    };

    // Restore the terminal if something panics while raw mode is active.
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        ratatui::restore();
        default_hook(info);
    }));

    let mut session = TerminalSession::new()?;
    session.terminal_mut().clear()?;
    run(
        session.terminal_mut(),
        App::new(initial_target, options),
    )
}

/// Owns the raw-mode terminal so every exit path leaves it usable again.
struct TerminalSession {
    terminal: Terminal<CrosstermBackend<io::Stdout>>,
}

impl TerminalSession {
    fn new() -> io::Result<Self> {
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        if let Err(error) = execute!(stdout, EnterAlternateScreen) {
            // Raw mode is on but the guard does not exist yet, so undo it here.
            let _ = disable_raw_mode();
            return Err(error);
        }
        match Terminal::new(CrosstermBackend::new(stdout)) {
            Ok(terminal) => Ok(Self { terminal }),
            Err(error) => {
                let _ = execute!(io::stdout(), LeaveAlternateScreen);
                let _ = disable_raw_mode();
                Err(error)
            }
        }
    }

    fn terminal_mut(&mut self) -> &mut Terminal<CrosstermBackend<io::Stdout>> {
        &mut self.terminal
    }
}

impl Drop for TerminalSession {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(self.terminal.backend_mut(), LeaveAlternateScreen);
        let _ = self.terminal.show_cursor();
    }
}

fn parse_args() -> Result<(Option<String>, ScanOptions), String> {
    let mut options = ScanOptions::default();
    let mut target = None;
    let mut args = std::env::args().skip(1);

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                print_help();
                std::process::exit(0);
            }
            "--nmap" => options.nmap = true,
            "--sample" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--sample requires a percentage".to_string())?;
                let sample: u8 = value
                    .parse()
                    .map_err(|_| format!("invalid --sample value: {value}"))?;
                if !(1..=100).contains(&sample) {
                    return Err("--sample must be between 1 and 100".to_string());
                }
                options.sample_percent = sample;
            }
            "--stop-after" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--stop-after requires a count".to_string())?;
                options.stop_after = value
                    .parse()
                    .map_err(|_| format!("invalid --stop-after value: {value}"))?;
            }
            "--concurrency" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--concurrency requires a number".to_string())?;
                let concurrency: usize = value
                    .parse()
                    .map_err(|_| format!("invalid --concurrency value: {value}"))?;
                if concurrency == 0 {
                    return Err("--concurrency must be at least 1".to_string());
                }
                options.concurrency = concurrency;
            }
            "--timeout" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--timeout requires milliseconds".to_string())?;
                let milliseconds: u64 = value
                    .parse()
                    .map_err(|_| format!("invalid --timeout value: {value}"))?;
                if milliseconds == 0 {
                    return Err("--timeout must be at least 1 ms".to_string());
                }
                options.timeout = Duration::from_millis(milliseconds);
            }
            _ if arg.starts_with('-') => return Err(format!("unknown option: {arg}")),
            _ => {
                if target.replace(arg.clone()).is_some() {
                    return Err("only one target can be given".to_string());
                }
            }
        }
    }

    Ok((target, options))
}

fn print_help() {
    println!(
        "nctui — find open Minecraft servers fast\n\n\
         Usage: nctui [OPTIONS] [TARGET]\n\n\
         TARGET: IPv4 CIDR (192.168.1.0/24), single IPv4, two-letter country code\n\
         (DE, US), or any nmap target such as a range or hostname. Defaults to\n\
         {DEFAULT_TARGET}.\n\n\
         Options:\n\
           --sample <1-100>     scan a random percentage of addresses (default 100)\n\
           --stop-after <N>     stop after N open ports are found (default 0 = never)\n\
           --concurrency <N>    concurrent connections (default auto-tuned)\n\
           --timeout <MS>       per-connection timeout in ms (default 400)\n\
           --nmap               force nmap instead of the built-in fast scanner\n\
           -h, --help           show this help\n\n\
         IPv4 ranges and country codes use the built-in connect scanner; nmap is\n\
         used for hostnames and other target syntax. In the TUI: s scan, x stop,\n\
         c copy the selected IP, q quit."
    );
}

fn run(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>, mut app: App) -> io::Result<()> {
    loop {
        app.drain_events();
        terminal.draw(|frame| app.draw(frame))?;

        if app.should_quit {
            return Ok(());
        }

        if event::poll(Duration::from_millis(80))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    app.handle_key(key);
                }
            }
        }
    }
}
