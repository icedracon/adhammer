//! Terminal UX: colored section headers, status glyphs, and a live spinner (with elapsed time)
//! for operations that wait on the network. Color + animation auto-disable when the stream isn't
//! a TTY or `NO_COLOR` is set, so piped/redirected output stays clean and machine-parsable.

use std::io::{IsTerminal, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

fn no_color() -> bool {
    std::env::var_os("NO_COLOR").is_some()
}
/// `CLICOLOR_FORCE=1` forces styling even when the stream is piped (e.g. into `less -R`).
fn force_color() -> bool {
    std::env::var("CLICOLOR_FORCE").is_ok_and(|v| !v.is_empty() && v != "0")
}
fn stdout_tty() -> bool {
    !no_color() && (force_color() || std::io::stdout().is_terminal())
}
fn stderr_tty() -> bool {
    !no_color() && (force_color() || std::io::stderr().is_terminal())
}

// SGR codes.
const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[90m";
const RED: &str = "\x1b[31m";
const GREEN: &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";
const CYAN: &str = "\x1b[36m";

fn paint(on: bool, code: &str, s: &str) -> String {
    if on {
        format!("{code}{s}{RESET}")
    } else {
        s.to_string()
    }
}

/// Dim styling for secondary text on stdout (returns plain when not a TTY).
pub fn dim(s: &str) -> String {
    paint(stdout_tty(), DIM, s)
}
/// Bold-cyan accent for a value on stdout.
pub fn accent(s: &str) -> String {
    paint(stdout_tty(), &format!("{BOLD}{CYAN}"), s)
}

/// A section header on stdout: `▸ TITLE` in bold cyan, with a dim rule underneath.
pub fn header(title: &str) {
    if stdout_tty() {
        println!("\n{BOLD}{CYAN}▸ {title}{RESET}");
        println!("{DIM}{}{RESET}", "─".repeat(title.chars().count() + 2));
    } else {
        println!("\n== {title} ==");
    }
}

/// A `key: value` line on stdout, key dimmed.
pub fn field(key: &str, val: &str) {
    if stdout_tty() {
        println!("  {DIM}{key}:{RESET} {val}");
    } else {
        println!("  {key}: {val}");
    }
}

// ---- status glyphs (stderr, so they never pollute machine stdout) --------------------

fn glyph(color: &str, ascii: &str, uni: &str) -> String {
    if stderr_tty() {
        format!("{color}{uni}{RESET}")
    } else {
        ascii.to_string()
    }
}

/// Success line, e.g. `✓ 42 objects collected`.
pub fn ok(msg: &str) {
    eprintln!("{} {msg}", glyph(GREEN, "[+]", "✓"));
}
/// Warning / attention line, e.g. a finding.
pub fn warn(msg: &str) {
    eprintln!("{} {msg}", glyph(YELLOW, "[!]", "▲"));
}
/// Failure line.
pub fn bad(msg: &str) {
    eprintln!("{} {msg}", glyph(RED, "[-]", "✗"));
}
/// Neutral informational line.
pub fn info(msg: &str) {
    eprintln!("{} {msg}", glyph(CYAN, "[*]", "•"));
}

// ---- spinner --------------------------------------------------------------------------

/// A live "…in progress" indicator for a network wait. On a TTY it animates a braille spinner
/// with an elapsed-seconds counter on stderr; otherwise it prints a single start line so the
/// user still knows what's happening. Always finish it with [`done`](Spinner::done) /
/// [`done_warn`](Spinner::done_warn) to clear the line and print the outcome.
pub struct Spinner {
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl Spinner {
    pub fn start(msg: impl Into<String>) -> Self {
        let msg = msg.into();
        let stop = Arc::new(AtomicBool::new(false));
        // Animate only on a real TTY — piped/redirected runs get a single start line instead.
        if !std::io::stderr().is_terminal() {
            eprintln!("[*] {msg}…");
            return Spinner { stop, handle: None };
        }
        let flag = stop.clone();
        let handle = std::thread::spawn(move || {
            let frames = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
            let start = Instant::now();
            let mut i = 0usize;
            while !flag.load(Ordering::Relaxed) {
                let secs = start.elapsed().as_secs();
                eprint!(
                    "\r{CYAN}{}{RESET} {msg} {DIM}({secs}s){RESET} ",
                    frames[i % frames.len()]
                );
                let _ = std::io::stderr().flush();
                i += 1;
                std::thread::sleep(Duration::from_millis(90));
            }
        });
        Spinner {
            stop,
            handle: Some(handle),
        }
    }

    fn stop_thread(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
            eprint!("\r\x1b[2K"); // clear the spinner line
            let _ = std::io::stderr().flush();
        }
    }

    /// Stop the spinner and print a success line.
    pub fn done(mut self, msg: &str) {
        self.stop_thread();
        ok(msg);
    }

    /// Stop the spinner and print a warning line (e.g. "0 hosts up").
    pub fn done_warn(mut self, msg: &str) {
        self.stop_thread();
        warn(msg);
    }
}

impl Drop for Spinner {
    fn drop(&mut self) {
        // Guarantee the animation thread is torn down even on an early return / `?`.
        self.stop_thread();
    }
}
