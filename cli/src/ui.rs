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

fn pace_enabled() -> bool {
    stderr_tty() && std::env::var("ADHAMMER_UI_PACE").map_or(true, |v| v != "0")
}

fn pace_ms(var: &str, default_ms: u64) -> u64 {
    std::env::var(var)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(default_ms)
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

pub fn accent_err(s: &str) -> String {
    paint(stderr_tty(), &format!("{BOLD}{CYAN}"), s)
}
pub fn red_err(s: &str) -> String {
    paint(stderr_tty(), &format!("{BOLD}{RED}"), s)
}
pub fn yellow_err(s: &str) -> String {
    paint(stderr_tty(), YELLOW, s)
}
pub fn green_err(s: &str) -> String {
    paint(stderr_tty(), GREEN, s)
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

/// A section header on stderr for narrated interactive flows.
pub fn header_err(title: &str) {
    if stderr_tty() {
        eprintln!("\n{BOLD}{CYAN}▸ {title}{RESET}");
        eprintln!("{DIM}{}{RESET}", "─".repeat(title.chars().count() + 2));
    } else {
        eprintln!("\n== {title} ==");
    }
}

/// A `key: value` line on stderr, key dimmed.
pub fn field_err(key: &str, val: &str) {
    if stderr_tty() {
        eprintln!("  {DIM}{key}:{RESET} {val}");
    } else {
        eprintln!("  {key}: {val}");
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

/// A neutral guide line without a status glyph.
pub fn note(msg: &str) {
    if stderr_tty() {
        eprintln!("{DIM}{msg}{RESET}");
    } else {
        eprintln!("{msg}");
    }
}

#[derive(Clone, Copy)]
pub enum OutcomeKind {
    Validated,
    Clean,
    Skipped,
    Failed,
    Blocked,
    Exported,
}

impl OutcomeKind {
    fn label(self) -> &'static str {
        match self {
            OutcomeKind::Validated => "validated",
            OutcomeKind::Clean => "clean",
            OutcomeKind::Skipped => "skipped",
            OutcomeKind::Failed => "failed",
            OutcomeKind::Blocked => "blocked",
            OutcomeKind::Exported => "exported",
        }
    }

    fn color(self) -> &'static str {
        match self {
            OutcomeKind::Validated | OutcomeKind::Clean | OutcomeKind::Exported => GREEN,
            OutcomeKind::Skipped => YELLOW,
            OutcomeKind::Failed | OutcomeKind::Blocked => RED,
        }
    }

    fn ascii(self) -> &'static str {
        match self {
            OutcomeKind::Validated => "[ok]",
            OutcomeKind::Clean => "[ok]",
            OutcomeKind::Skipped => "[skip]",
            OutcomeKind::Failed => "[fail]",
            OutcomeKind::Blocked => "[block]",
            OutcomeKind::Exported => "[save]",
        }
    }
}

fn outcome_badge(kind: OutcomeKind) -> String {
    if stderr_tty() {
        format!("{}{}{}", kind.color(), kind.label(), RESET)
    } else {
        kind.ascii().to_string()
    }
}

pub fn outcome(kind: OutcomeKind, msg: &str) {
    eprintln!("{} {msg}", outcome_badge(kind));
}

pub fn linger(ms: u64) {
    if pace_enabled() && ms > 0 {
        std::thread::sleep(Duration::from_millis(ms));
    }
}

#[derive(Clone, Copy)]
pub enum Pace {
    Fast,
    Normal,
    Important,
    Critical,
}

pub fn beat() {
    beat_for(Pace::Normal);
}

pub fn hold() {
    hold_for(Pace::Important);
}

pub fn beat_for(pace: Pace) {
    linger(match pace {
        Pace::Fast => pace_ms("ADHAMMER_UI_FAST_MS", 140),
        Pace::Normal => pace_ms("ADHAMMER_UI_LINGER_MS", 420),
        Pace::Important => pace_ms("ADHAMMER_UI_IMPORTANT_MS", 780),
        Pace::Critical => pace_ms("ADHAMMER_UI_CRITICAL_MS", 1300),
    });
}

pub fn hold_for(pace: Pace) {
    linger(match pace {
        Pace::Fast => pace_ms("ADHAMMER_UI_HOLD_FAST_MS", 260),
        Pace::Normal => pace_ms("ADHAMMER_UI_HOLD_NORMAL_MS", 620),
        Pace::Important => pace_ms("ADHAMMER_UI_HOLD_MS", 1200),
        Pace::Critical => pace_ms("ADHAMMER_UI_HOLD_CRITICAL_MS", 1900),
    });
}

pub fn menu_legend() {
    note("Controls: Enter=default  number=choose  Ctrl+C=cancel");
}

pub fn note_story(msg: &str, pace: Pace) {
    note(msg);
    beat_for(pace);
}

pub fn field_story_err(key: &str, val: &str, pace: Pace) {
    field_err(key, val);
    beat_for(pace);
}

#[derive(Clone, Copy)]
pub enum Tone {
    Accent,
    Good,
    Warn,
    Bad,
    Dim,
}

pub fn sticker(label: &str, tone: Tone) -> String {
    let raw = format!("[{}]", label);
    match tone {
        Tone::Accent => accent_err(&raw),
        Tone::Good => green_err(&raw),
        Tone::Warn => yellow_err(&raw),
        Tone::Bad => red_err(&raw),
        Tone::Dim => dim_err(&raw),
    }
}

pub struct Phase {
    label: String,
    start: Instant,
}

impl Phase {
    pub fn start(step: &str) -> Self {
        info(step);
        beat_for(Pace::Normal);
        Self {
            label: step.to_string(),
            start: Instant::now(),
        }
    }

    pub fn finish(self, kind: OutcomeKind, msg: &str) {
        let secs = self.start.elapsed().as_secs_f32();
        outcome(kind, &format!("{msg} {}", elapsed_tag(secs)));
        beat();
    }

    #[allow(dead_code)]
    pub fn label(&self) -> &str {
        &self.label
    }
}

fn elapsed_tag(secs: f32) -> String {
    if stderr_tty() {
        format!("{DIM}({secs:.1}s){RESET}")
    } else {
        format!("({secs:.1}s)")
    }
}

pub fn proof_block(kind: &str, evidence: &str) {
    let ev = evidence.trim();
    if ev.is_empty() {
        return;
    }
    const MAX_LINES: usize = 12;
    const MAX_LEN: usize = 160;
    eprintln!(
        "     {} {}",
        sticker("PROOF", Tone::Good),
        dim_err(&kind.to_uppercase())
    );
    beat_for(Pace::Important);
    let lines: Vec<&str> = ev.lines().collect();
    for line in lines.iter().take(MAX_LINES) {
        let n = line.chars().count();
        let shown = if n > MAX_LEN {
            let head: String = line.chars().take(MAX_LEN).collect();
            format!("{head}... [+{} chars]", n - MAX_LEN)
        } else {
            (*line).to_string()
        };
        eprintln!("     {}", dim_err(&shown));
        beat_for(Pace::Fast);
    }
    if lines.len() > MAX_LINES {
        eprintln!(
            "     {}",
            dim_err(&format!(
                "... (+{} more line(s) - full proof in the export)",
                lines.len() - MAX_LINES
            ))
        );
    }
    hold_for(Pace::Important);
}

pub fn artifact(label: &str, path: &str) {
    outcome(
        OutcomeKind::Exported,
        &format!("{} {label} -> {path}", sticker("EXPORT", Tone::Accent)),
    );
    beat_for(Pace::Normal);
}

pub fn finish_card(title: &str, lines: &[(&str, String)]) {
    header_err(title);
    for (key, value) in lines {
        field_err(key, value);
        beat_for(Pace::Normal);
    }
    hold_for(Pace::Critical);
}

fn dim_err(s: &str) -> String {
    paint(stderr_tty(), DIM, s)
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
