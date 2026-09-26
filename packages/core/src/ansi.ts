// SPDX-License-Identifier: Apache-2.0
//
// The parsing half of the sanitizing log viewer (T-09, ADR-0007 §5). Build
// logs are attacker-controlled bytes: a fork PR decides what its jobs print.
// This parser turns them into plain text plus a small, closed set of style
// attributes. Only SGR (color and text style) escapes are interpreted; every
// other escape sequence (OSC hyperlinks and titles, cursor movement, device
// control strings) and every control character is dropped. The output is
// data for React to render as text, never HTML, and styles map to fixed
// classes, never to inline CSS.

/** One of the 16 standard terminal colors: 0-7 normal, 8-15 bright. */
export type AnsiColor = number;

/** The text attributes the viewer supports. Absent means off or default. */
export interface AnsiStyle {
  fg?: AnsiColor;
  bg?: AnsiColor;
  bold?: boolean;
  dim?: boolean;
  italic?: boolean;
  underline?: boolean;
  inverse?: boolean;
  strike?: boolean;
}

/** A run of text sharing one style. */
export interface AnsiSpan {
  text: string;
  style: AnsiStyle;
}

/** One log line. `truncated` means characters past the line limit were dropped. */
export interface AnsiLine {
  spans: AnsiSpan[];
  truncated: boolean;
}

/** Default maximum characters kept per line; the rest are dropped. */
export const MAX_LINE_CHARS = 16_384;

/** Maximum styled spans per line; later style changes on the line are ignored. */
export const MAX_SPANS_PER_LINE = 256;

// Longest escape sequence buffered while waiting for its terminator. Longer
// ones are abandoned (dropped) so a stream cannot make the parser buffer
// without bound.
const MAX_ESCAPE_CHARS = 4_096;

const ESC = "\x1b";
const BEL = "\x07";

type EscapeState =
  | "none"
  | "esc" // saw ESC
  | "csi" // ESC [
  | "string" // ESC ] / P / X / ^ / _ : ends at BEL or ST (ESC \)
  | "string-esc" // saw ESC inside a string, expecting "\"
  | "nf"; // ESC followed by intermediates (0x20-0x2f), ends at 0x30-0x7e

/**
 * Parses ANSI-colored terminal output incrementally. Feed decoded text with
 * `push` (escape sequences may be split across calls); completed lines are
 * returned, and `pending()` is the line still being written.
 *
 * Carriage returns follow terminal progress-bar semantics: `\r\n` ends a
 * line, and a lone `\r` starts the current line over.
 */
export class AnsiParser {
  private style: AnsiStyle = {};
  private spans: AnsiSpan[] = [];
  private text = "";
  private lineChars = 0;
  private truncated = false;
  private state: EscapeState = "none";
  private seq = "";
  private stringChars = 0;
  private sawCR = false;
  private readonly maxLineChars: number;

  constructor(opts: { maxLineChars?: number } = {}) {
    this.maxLineChars = opts.maxLineChars ?? MAX_LINE_CHARS;
  }

  /** Parses the next piece of output and returns the lines it completed. */
  push(input: string): AnsiLine[] {
    const out: AnsiLine[] = [];
    for (const ch of input) {
      this.step(ch, out);
    }
    return out;
  }

  /** The unfinished last line, or null when it is empty. */
  pending(): AnsiLine | null {
    const spans = this.currentSpans();
    return spans.length > 0 || this.truncated ? { spans, truncated: this.truncated } : null;
  }

  /** Ends the input: returns the unfinished last line, if any, and resets. */
  end(): AnsiLine | null {
    const last = this.pending();
    this.reset();
    return last;
  }

  /** Forgets all state, e.g. when a job's log restarts for a new attempt. */
  reset(): void {
    this.style = {};
    this.spans = [];
    this.text = "";
    this.lineChars = 0;
    this.truncated = false;
    this.state = "none";
    this.seq = "";
    this.stringChars = 0;
    this.sawCR = false;
  }

  private step(ch: string, out: AnsiLine[]): void {
    if (this.state !== "none") {
      const inString = this.state === "string" || this.state === "string-esc";
      // Line breaks still end lines inside short escapes, so a broken
      // sequence cannot merge or hide lines (strings are bounded instead).
      if (inString || (ch !== "\n" && ch !== "\r")) {
        this.escape(ch);
        return;
      }
      this.endEscape();
    }
    if (this.sawCR) {
      this.sawCR = false;
      if (ch === "\n") {
        out.push(this.finishLine());
        return;
      }
      // A lone CR: the line is being redrawn, keep only what follows.
      this.clearLine();
    }
    if (ch === "\n") {
      out.push(this.finishLine());
      return;
    }
    if (ch === "\r") {
      this.sawCR = true;
      return;
    }
    if (ch === ESC) {
      this.state = "esc";
      this.seq = "";
      return;
    }
    if (ch === "\t") {
      this.append(ch);
      return;
    }
    const code = ch.codePointAt(0) ?? 0;
    // C0 controls, DEL, and C1 controls (including the 8-bit CSI 0x9b) are
    // dropped, not interpreted.
    if (code < 0x20 || (code >= 0x7f && code <= 0x9f)) return;
    // Bidirectional embeddings, overrides, and isolates reorder how text is
    // displayed ("Trojan Source"); show them as a replacement character.
    if ((code >= 0x202a && code <= 0x202e) || (code >= 0x2066 && code <= 0x2069)) {
      this.append("�");
      return;
    }
    this.append(ch);
  }

  private escape(ch: string): void {
    const code = ch.codePointAt(0) ?? 0;
    switch (this.state) {
      case "esc":
        if (ch === "[") {
          this.state = "csi";
        } else if (ch === "]" || ch === "P" || ch === "X" || ch === "^" || ch === "_") {
          this.state = "string";
        } else if (code >= 0x20 && code <= 0x2f) {
          this.state = "nf";
        } else {
          // A two-character escape (ESC 7, ESC c, ...) or a stray ESC: drop it.
          this.state = "none";
        }
        return;
      case "csi":
        if (code >= 0x40 && code <= 0x7e) {
          // Private-mode sequences (ESC[>4;2m, ESC[?...) are not SGR.
          if (ch === "m" && /^[0-9;:]*$/.test(this.seq)) this.sgr(this.seq);
          this.endEscape();
          return;
        }
        // Other C0 controls inside a sequence are ignored.
        if (code < 0x20) return;
        if (code > 0x3f || this.seq.length >= 64) {
          // Malformed or oversized: abandon the sequence.
          this.endEscape();
          return;
        }
        this.seq += ch;
        return;
      case "string":
        // OSC, DCS, SOS, PM, APC: the whole string is dropped.
        if (ch === BEL) {
          this.endEscape();
        } else if (ch === ESC) {
          this.state = "string-esc";
        } else if (++this.stringChars > MAX_ESCAPE_CHARS) {
          this.endEscape();
        }
        return;
      case "string-esc":
        // ST (ESC \\) ends the string. ESC followed by anything else also ends
        // it and starts a new escape sequence (ECMA-48), so interleaved
        // escapes cannot keep a string open.
        this.endEscape();
        if (ch !== "\\") {
          this.state = "esc";
          this.escape(ch);
        }
        return;
      case "nf":
        if (code < 0x20) return;
        if (code > 0x2f || ++this.stringChars > 16) this.endEscape();
        return;
      case "none":
        return;
    }
  }

  private endEscape(): void {
    this.state = "none";
    this.seq = "";
    this.stringChars = 0;
  }

  private append(ch: string): void {
    if (this.lineChars >= this.maxLineChars) {
      this.truncated = true;
      return;
    }
    this.text += ch;
    this.lineChars++;
  }

  private flushText(): void {
    if (this.text === "") return;
    const last = this.spans[this.spans.length - 1];
    // Past the span budget the rest of the line keeps the last span's style,
    // so per-character color changes cannot multiply DOM nodes.
    if (last && (sameStyle(last.style, this.style) || this.spans.length >= MAX_SPANS_PER_LINE)) {
      last.text += this.text;
    } else {
      this.spans.push({ text: this.text, style: this.style });
    }
    this.text = "";
  }

  private currentSpans(): AnsiSpan[] {
    this.flushText();
    return this.spans.map((s) => ({ text: s.text, style: s.style }));
  }

  private finishLine(): AnsiLine {
    this.flushText();
    const line = { spans: this.spans, truncated: this.truncated };
    this.spans = [];
    this.lineChars = 0;
    this.truncated = false;
    return line;
  }

  private clearLine(): void {
    this.spans = [];
    this.text = "";
    this.lineChars = 0;
    this.truncated = false;
  }

  /** Applies a Select Graphic Rendition parameter string, e.g. "1;31". */
  private sgr(params: string): void {
    this.flushText();
    const parts = params === "" ? ["0"] : params.split(/[;:]/);
    let s: AnsiStyle = { ...this.style };
    for (let i = 0; i < parts.length; i++) {
      const n = parts[i] === "" ? 0 : Number(parts[i]);
      if (!Number.isInteger(n)) continue;
      if (n === 0) {
        s = {};
      } else if (n === 1) s.bold = true;
      else if (n === 2) s.dim = true;
      else if (n === 3) s.italic = true;
      else if (n === 4) s.underline = true;
      else if (n === 7) s.inverse = true;
      else if (n === 9) s.strike = true;
      else if (n === 22) {
        delete s.bold;
        delete s.dim;
      } else if (n === 23) delete s.italic;
      else if (n === 24) delete s.underline;
      else if (n === 27) delete s.inverse;
      else if (n === 29) delete s.strike;
      else if (n >= 30 && n <= 37) s.fg = n - 30;
      else if (n === 39) delete s.fg;
      else if (n >= 40 && n <= 47) s.bg = n - 40;
      else if (n === 49) delete s.bg;
      else if (n >= 90 && n <= 97) s.fg = n - 90 + 8;
      else if (n >= 100 && n <= 107) s.bg = n - 100 + 8;
      else if (n === 38 || n === 48) {
        const [color, used] = extendedColor(parts, i + 1);
        i += used;
        if (color !== undefined) {
          if (n === 38) s.fg = color;
          else s.bg = color;
        }
      }
    }
    this.style = s;
  }
}

/**
 * Reads a 256-color (`5;n`) or truecolor (`2;r;g;b`) argument starting at
 * `parts[i]` and returns the nearest of the 16 standard colors, plus how many
 * parameters were consumed. Colors map to the 16-color palette so the viewer
 * only ever uses its fixed, theme-aware classes.
 */
function extendedColor(parts: string[], i: number): [AnsiColor | undefined, number] {
  const mode = Number(parts[i]);
  if (mode === 5) {
    const n = Number(parts[i + 1]);
    if (!Number.isInteger(n) || n < 0 || n > 255) return [undefined, 2];
    return [xterm256To16(n), 2];
  }
  if (mode === 2) {
    // Accept both 38;2;r;g;b and the colon form 38:2::r:g:b (empty color space).
    let j = i + 1;
    if (parts.length - j >= 4 && parts[j] === "") j++;
    const rgb = [parts[j], parts[j + 1], parts[j + 2]].map(Number);
    const used = j + 3 - i;
    if (rgb.some((c) => !Number.isInteger(c) || c < 0 || c > 255)) return [undefined, used];
    return [nearest16(rgb[0] ?? 0, rgb[1] ?? 0, rgb[2] ?? 0), used];
  }
  return [undefined, 1];
}

// The xterm default palette for the 16 standard colors.
const PALETTE: [number, number, number][] = [
  [0, 0, 0], [205, 0, 0], [0, 205, 0], [205, 205, 0], [0, 0, 238], [205, 0, 205], [0, 205, 205], [229, 229, 229],
  [127, 127, 127], [255, 0, 0], [0, 255, 0], [255, 255, 0], [92, 92, 255], [255, 0, 255], [0, 255, 255], [255, 255, 255],
];

/** Maps an xterm 256-color index to the nearest of the 16 standard colors. */
export function xterm256To16(n: number): AnsiColor {
  if (n < 16) return n;
  if (n >= 232) {
    const v = 8 + (n - 232) * 10;
    return nearest16(v, v, v);
  }
  const c = n - 16;
  const level = (x: number) => (x === 0 ? 0 : 55 + x * 40);
  return nearest16(level(Math.floor(c / 36)), level(Math.floor(c / 6) % 6), level(c % 6));
}

function nearest16(r: number, g: number, b: number): AnsiColor {
  let best = 0;
  let bestDist = Infinity;
  PALETTE.forEach(([pr, pg, pb], idx) => {
    const d = (r - pr) ** 2 + (g - pg) ** 2 + (b - pb) ** 2;
    if (d < bestDist) {
      bestDist = d;
      best = idx;
    }
  });
  return best;
}

function sameStyle(a: AnsiStyle, b: AnsiStyle): boolean {
  return (
    a.fg === b.fg &&
    a.bg === b.bg &&
    a.bold === b.bold &&
    a.dim === b.dim &&
    a.italic === b.italic &&
    a.underline === b.underline &&
    a.inverse === b.inverse &&
    a.strike === b.strike
  );
}

/** Parses a complete log into lines (a convenience over AnsiParser). */
export function parseAnsi(text: string, opts: { maxLineChars?: number } = {}): AnsiLine[] {
  const p = new AnsiParser(opts);
  const lines = p.push(text);
  const last = p.end();
  if (last) lines.push(last);
  return lines;
}
