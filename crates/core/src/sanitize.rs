//! Strip terminal control sequences from network-derived text.
//!
//! WS-OUTPUT-SANITIZE (1.4.10): a hostile target can embed ANSI CSI escapes
//! (`ESC [ 31 m`), operating-system-command sequences (`ESC ] 0 ; title BEL`)
//! or bare C0 controls (BEL, backspace, carriage-return, form-feed) into any
//! string an operator later prints. Without stripping, those bytes can:
//!   - inject fake ANSI colouring that misrepresents severity;
//!   - overwrite prior lines via `CR` to hide findings;
//!   - retitle the operator's terminal via OSC 0/2;
//!   - trigger a beep flood via `\x07`;
//!   - break subsequent output layout via C1 controls.
//!
//! Every string that leaves the network (LDAP attribute values, GPO comments,
//! server banners, WinRM stderr, SMB share descriptions, HTTP body extracts)
//! passes through [`sanitize_terminal_output`] before it reaches stdout,
//! stderr, a `Finding.detail` string, or any report body (JSON string values,
//! HTML text nodes, Markdown paragraph text, plain-text lines).
//!
//! The function operates on `&str`; input is guaranteed valid UTF-8, and the
//! implementation never introduces invalid UTF-8. C1 Unicode code points
//! (U+0080..=U+009F) are additionally stripped because some terminals still
//! interpret them as legacy 8-bit control codes.

/// Strip terminal control sequences that a hostile network peer could have
/// embedded into `s`.
///
/// Removes:
/// - C0 controls (0x00..=0x1F) EXCEPT `\n` (0x0A) and `\t` (0x09)
/// - `DEL` (0x7F)
/// - Unicode C1 controls (U+0080..=U+009F)
/// - CSI sequences: `ESC [ (0x30..=0x3F)* (0x20..=0x2F)* <final 0x40..=0x7E>`
/// - OSC sequences: `ESC ] ... (BEL | ESC \)`  (with a per-call byte cap)
/// - Any other `ESC <byte>` two-byte sequence
///
/// Preserves valid UTF-8 code points that are not controls.
pub fn sanitize_terminal_output(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;

    while i < bytes.len() {
        let b = bytes[i];
        match b {
            // ESC-initiated sequence.
            0x1B => {
                i = skip_escape_sequence(bytes, i);
            }
            // Preserved whitespace.
            b'\n' | b'\t' => {
                out.push(b as char);
                i += 1;
            }
            // Strip C0 controls + DEL. (0x1B handled above.)
            0x00..=0x1F | 0x7F => {
                i += 1;
            }
            // ASCII printable.
            0x20..=0x7E => {
                out.push(b as char);
                i += 1;
            }
            // UTF-8 multibyte sequence. `s` is valid UTF-8, so the trailing
            // continuation bytes (0x80..=0xBF) always follow a leading byte
            // (>= 0xC2); C1 controls (U+0080..=U+009F) encode as two bytes
            // 0xC2 0x80..=0xC2 0x9F — detect and drop that specific range.
            _ => {
                let ch_start = i;
                i += 1;
                while i < bytes.len() && (bytes[i] & 0xC0) == 0x80 {
                    i += 1;
                }
                let chunk = &bytes[ch_start..i];
                if is_utf8_c1(chunk) {
                    // Drop.
                } else {
                    // SAFETY: chunk is a well-formed UTF-8 code point taken
                    // from a `&str`, so `from_utf8_unchecked` is sound; use
                    // the checked form anyway for defence-in-depth.
                    match std::str::from_utf8(chunk) {
                        Ok(s) => out.push_str(s),
                        Err(_) => out.push('\u{FFFD}'),
                    }
                }
            }
        }
    }

    out
}

/// Called with `bytes[start] == 0x1B`. Advances past the whole escape
/// sequence and returns the index of the first byte after it.
fn skip_escape_sequence(bytes: &[u8], start: usize) -> usize {
    // Bare ESC at end of input: drop it.
    if start + 1 >= bytes.len() {
        return start + 1;
    }
    match bytes[start + 1] {
        // CSI: ESC [ P* I* F   where P=0x30..=0x3F, I=0x20..=0x2F, F=0x40..=0x7E.
        b'[' => {
            let mut i = start + 2;
            while i < bytes.len() && (0x30..=0x3F).contains(&bytes[i]) {
                i += 1;
            }
            while i < bytes.len() && (0x20..=0x2F).contains(&bytes[i]) {
                i += 1;
            }
            if i < bytes.len() && (0x40..=0x7E).contains(&bytes[i]) {
                i += 1;
            }
            i
        }
        // OSC: ESC ] ... (BEL | ESC \)   cap at 512 bytes of payload to bound
        // pathological cases where the terminator never arrives; drop the
        // whole malformed sequence in that case.
        b']' => {
            let mut i = start + 2;
            let cap = i.saturating_add(512);
            while i < bytes.len() && i < cap {
                if bytes[i] == 0x07 {
                    i += 1;
                    return i;
                }
                if bytes[i] == 0x1B && i + 1 < bytes.len() && bytes[i + 1] == b'\\' {
                    return i + 2;
                }
                i += 1;
            }
            i
        }
        // Any other two-byte escape (7-bit C1: ESC N, ESC O, ESC =, ESC 7, …).
        _ => start + 2,
    }
}

fn is_utf8_c1(chunk: &[u8]) -> bool {
    chunk.len() == 2 && chunk[0] == 0xC2 && (0x80..=0x9F).contains(&chunk[1])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_csi_color_and_bel_and_backspace() {
        assert_eq!(sanitize_terminal_output("\x1b[31m\x07inject\x08"), "inject");
    }

    #[test]
    fn preserves_ascii_printable_and_newlines_and_tabs() {
        let s = "hello\tworld\nend";
        assert_eq!(sanitize_terminal_output(s), s);
    }

    #[test]
    fn strips_carriage_return_used_to_overwrite_previous_line() {
        assert_eq!(sanitize_terminal_output("SAFE\rEVIL"), "SAFEEVIL");
    }

    #[test]
    fn strips_osc_set_window_title_bel_terminated() {
        assert_eq!(
            sanitize_terminal_output("\x1b]0;attacker owned\x07visible"),
            "visible"
        );
    }

    #[test]
    fn strips_osc_st_terminated() {
        assert_eq!(sanitize_terminal_output("\x1b]2;title\x1b\\rest"), "rest");
    }

    #[test]
    fn drops_unterminated_osc_up_to_cap() {
        let mut s = String::from("\x1b]");
        s.push_str(&"A".repeat(1024));
        let out = sanitize_terminal_output(&s);
        assert!(
            out.len() < 700,
            "unterminated OSC must be capped, got {} bytes",
            out.len()
        );
    }

    #[test]
    fn strips_arbitrary_c0_but_keeps_newline_and_tab() {
        let s = "a\x00b\x01c\x1fd\x7fe\ttab\nnl";
        assert_eq!(sanitize_terminal_output(s), "abcde\ttab\nnl");
    }

    #[test]
    fn strips_unicode_c1_controls() {
        // U+0085 NEL and U+0090 DCS as UTF-8.
        let s = "before\u{0085}\u{0090}after";
        assert_eq!(sanitize_terminal_output(s), "beforeafter");
    }

    #[test]
    fn preserves_multibyte_utf8() {
        let s = "привет · café · 日本語";
        assert_eq!(sanitize_terminal_output(s), s);
    }

    #[test]
    fn strips_bare_esc_at_end_of_input() {
        assert_eq!(sanitize_terminal_output("data\x1b"), "data");
    }

    #[test]
    fn strips_two_byte_escape_sequences() {
        // ESC 7 (save cursor), ESC = (application keypad mode).
        assert_eq!(sanitize_terminal_output("a\x1b7b\x1b=c"), "abc");
    }

    #[test]
    fn empty_input_returns_empty() {
        assert_eq!(sanitize_terminal_output(""), "");
    }

    #[test]
    fn nested_and_mixed_sequences() {
        // Simulated hostile LDAP description embedding both CSI + OSC + bare C0.
        let s = "user\x1b[31m\x1b]0;pwned\x07\x00cn=alice\nend";
        assert_eq!(sanitize_terminal_output(s), "usercn=alice\nend");
    }

    #[test]
    fn csi_with_parameters_intermediates_and_final() {
        // ESC [ 1 ; 2 SP q   —   set cursor style.
        assert_eq!(sanitize_terminal_output("a\x1b[1;2 qb"), "ab");
    }

    #[test]
    fn del_stripped() {
        assert_eq!(sanitize_terminal_output("safe\x7fdel"), "safedel");
    }
}
