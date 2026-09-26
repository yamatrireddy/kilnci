// SPDX-License-Identifier: Apache-2.0

import { AnsiParser, type AnsiLine } from "./ansi";

/** Default number of lines a log view keeps; older lines are dropped. */
export const MAX_LOG_LINES = 10_000;

/** Default number of characters a log view keeps; older lines are dropped. */
export const MAX_LOG_CHARS = 4_000_000;

function lineChars(line: AnsiLine): number {
  let n = 0;
  for (const s of line.spans) n += s.text.length;
  return n;
}

/**
 * The lines of one job attempt's log, parsed incrementally from raw bytes.
 * It keeps only the most recent `maxLines` lines and `maxChars` characters so
 * a long log cannot grow the page without bound (T-10), and counts the lines
 * it dropped.
 */
export class LogBuffer {
  /** Completed lines, oldest first. Treat as read-only. */
  lines: AnsiLine[] = [];
  /** How many earlier lines were dropped to stay within `maxLines`. */
  dropped = 0;
  private parser: AnsiParser;
  // UTF-8 sequences can be split across chunks; stream mode stitches them.
  private decoder = new TextDecoder();
  private readonly maxLines: number;
  private readonly maxChars: number;
  private chars = 0;
  private charCounts: number[] = [];

  constructor(opts: { maxLines?: number; maxChars?: number; maxLineChars?: number } = {}) {
    this.maxLines = opts.maxLines ?? MAX_LOG_LINES;
    this.maxChars = opts.maxChars ?? MAX_LOG_CHARS;
    this.parser = new AnsiParser(opts.maxLineChars === undefined ? {} : { maxLineChars: opts.maxLineChars });
  }

  /** Appends raw log bytes. Invalid UTF-8 becomes U+FFFD. */
  pushBytes(bytes: Uint8Array): void {
    this.pushText(this.decoder.decode(bytes, { stream: true }));
  }

  /** Appends already-decoded log text. */
  pushText(text: string): void {
    for (const line of this.parser.push(text)) {
      const n = lineChars(line);
      this.lines.push(line);
      this.charCounts.push(n);
      this.chars += n;
    }
    this.trim();
  }

  /** The line still being written, if any. */
  pending(): AnsiLine | null {
    return this.parser.pending();
  }

  /** Clears everything, e.g. when the job starts a new attempt. */
  reset(): void {
    this.lines = [];
    this.charCounts = [];
    this.chars = 0;
    this.dropped = 0;
    this.parser.reset();
    this.decoder = new TextDecoder();
  }

  private trim(): void {
    // Trim in batches so appending stays amortized O(1).
    let excess = this.lines.length - this.maxLines;
    const overLines = excess > Math.max(1, this.maxLines / 10) || (excess > 0 && this.maxLines < 10);
    if (!overLines && this.chars <= this.maxChars) return;
    excess = Math.max(0, excess);
    let chars = this.chars;
    for (let i = 0; i < excess; i++) chars -= this.charCounts[i] ?? 0;
    // Drop to 90% of the character budget, so trimming is not repeated per line.
    while (chars > this.maxChars * 0.9 && excess < this.lines.length) {
      chars -= this.charCounts[excess] ?? 0;
      excess++;
    }
    if (excess === 0) return;
    this.lines = this.lines.slice(excess);
    this.charCounts = this.charCounts.slice(excess);
    this.chars = chars;
    this.dropped += excess;
  }
}
