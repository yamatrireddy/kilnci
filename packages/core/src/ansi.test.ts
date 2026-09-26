// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";

import { AnsiParser, displayText, LogBuffer, MAX_SPANS_PER_LINE, formatDuration, isFinishedStatus, isWaitingJob, parseAnsi, shortSha, statusLabel, xterm256To16, type AnsiLine } from "./index";

/** The visible text of each line. */
const texts = (lines: AnsiLine[]) => lines.map((l) => l.spans.map((s) => s.text).join(""));

describe("parseAnsi", () => {
  it("splits lines and keeps plain text", () => {
    expect(texts(parseAnsi("hello\nworld\n"))).toEqual(["hello", "world"]);
    expect(texts(parseAnsi("a\r\nb"))).toEqual(["a", "b"]);
    expect(texts(parseAnsi("\n\n"))).toEqual(["", ""]);
    expect(parseAnsi("")).toEqual([]);
  });

  it("applies SGR colors and styles", () => {
    const [line] = parseAnsi("\x1b[1;31merror\x1b[0m done \x1b[92mok\x1b[39m");
    expect(line?.spans).toEqual([
      { text: "error", style: { bold: true, fg: 1 } },
      { text: " done ", style: {} },
      { text: "ok", style: { fg: 10 } },
    ]);
  });

  it("handles every supported attribute and its reset", () => {
    const [line] = parseAnsi("\x1b[2;3;4;7;9;41;103ma\x1b[22;23;24;27;29;49mb\x1b[mc");
    expect(line?.spans).toEqual([
      { text: "a", style: { dim: true, italic: true, underline: true, inverse: true, strike: true, bg: 11 } },
      { text: "bc", style: {} },
    ]);
  });

  it("maps 256-color and truecolor to the 16-color palette", () => {
    const [line] = parseAnsi("\x1b[38;5;196ma\x1b[48;5;21mb\x1b[38;2;0;205;0mc\x1b[38:2::255:255:255md\x1b[38;5;999me");
    expect(line?.spans.map((s) => s.style)).toEqual([{ fg: 9 }, { fg: 9, bg: 4 }, { fg: 2, bg: 4 }, { fg: 15, bg: 4 }]);
    expect(texts(parseAnsi("\x1b[38;2;999;0;0mx"))).toEqual(["x"]);
    expect(xterm256To16(3)).toBe(3);
    expect(xterm256To16(232)).toBe(0);
    expect(xterm256To16(255)).toBe(7);
    expect(xterm256To16(16)).toBe(0);
  });

  it("merges adjacent text with the same style", () => {
    const [line] = parseAnsi("\x1b[31ma\x1b[31mb\x1b[1m\x1b[22mc");
    expect(line?.spans).toEqual([{ text: "abc", style: { fg: 1 } }]);
  });

  // T-09: nothing except SGR is interpreted, and control characters vanish.
  const dropped: [string, string, string][] = [
    ["OSC 8 hyperlink", "\x1b]8;;https://evil.example\x07click\x1b]8;;\x07", "click"],
    ["OSC title with ST", "\x1b]0;pwned\x1b\\text", "text"],
    ["DCS string", "\x1bPq#0;2;0;0;0\x1b\\after", "after"],
    ["APC string", "\x1b_payload\x07x", "x"],
    ["cursor movement", "a\x1b[2Ab\x1b[10;20Hc\x1b[2Jd", "abcd"],
    ["private mode SGR lookalike", "\x1b[>4;2mx\x1b[?25l", "x"],
    ["charset designation", "\x1b(Bx", "x"],
    ["two-character escapes", "\x1b7a\x1b8\x1bcb", "ab"],
    ["C0 controls", "a\x00b\x07c\x08d\x0be\x0cf", "abcdef"],
    ["DEL and C1 controls", "a\x7fb\x9b31mc\x85d", "ab31mcd"],
    ["a control inside CSI", "\x1b[31\x01mx", "x"],
    ["ESC inside a string (starts a new escape)", "\x1b]0;t\x1b[1mbold", "bold"],
  ];
  it.each(dropped)("drops %s", (_name, input, want) => {
    expect(texts(parseAnsi(input))).toEqual([want]);
  });

  it("keeps HTML as literal text", () => {
    expect(texts(parseAnsi('<img src=x onerror="alert(1)">'))).toEqual(['<img src=x onerror="alert(1)">']);
  });

  it("replaces bidi overrides so text cannot be visually reordered", () => {
    expect(texts(parseAnsi("a‮b⁦c⁩"))).toEqual(["a�b�c�"]);
  });

  it("keeps tabs and non-ASCII text", () => {
    expect(texts(parseAnsi("a\tb ✓ 日本 👩‍💻"))).toEqual(["a\tb ✓ 日本 👩‍💻"]);
  });

  it("treats a lone carriage return as a redraw of the line", () => {
    expect(texts(parseAnsi("10%\r50%\r100%\ndone"))).toEqual(["100%", "done"]);
  });

  it("truncates overlong lines and marks them", () => {
    const lines = parseAnsi(`${"x".repeat(20)}\nshort`, { maxLineChars: 8 });
    expect(texts(lines)).toEqual(["xxxxxxxx", "short"]);
    expect(lines.map((l) => l.truncated)).toEqual([true, false]);
  });

  it("abandons unterminated escape strings instead of buffering forever", () => {
    const [line] = parseAnsi(`\x1b]${"a".repeat(5000)}`);
    expect(line?.spans[0]?.text.length).toBeLessThan(1000);
    const [csi] = parseAnsi(`\x1b[${"1;".repeat(40)}mx`);
    expect(csi?.spans).toHaveLength(1);
    expect(csi?.spans[0]?.style).toEqual({});
    expect(csi?.spans[0]?.text.endsWith("mx")).toBe(true);
  });
});

describe("parser bounds (security review)", () => {
  it("cannot hide later output with ESC pairs inside a string", () => {
    const lines = parseAnsi(`\x1b]0;line1\nline2\n${"\x1bx".repeat(10_000)}visible?\n`);
    expect(texts(lines).at(-1)).toBe("visible?");
  });

  it("ends lines even inside a broken escape", () => {
    expect(texts(parseAnsi("a\x1b[1\nb"))).toEqual(["a", "b"]);
    expect(texts(parseAnsi("a\x1b(\nb"))).toEqual(["a", "b"]);
  });

  it("caps the spans on one line", () => {
    const colors = Array.from({ length: 2000 }, (_, i) => `\x1b[3${String(i % 2 === 0 ? 1 : 2)}mx`).join("");
    const [line] = parseAnsi(colors);
    expect(line?.spans.length).toBe(MAX_SPANS_PER_LINE);
    expect(line?.spans.map((s) => s.text).join("")).toHaveLength(2000);
  });
});

describe("AnsiParser", () => {
  it("handles escapes and CRLF split across chunks", () => {
    const p = new AnsiParser();
    expect(p.push("a\x1b[3")).toEqual([]);
    expect(p.push("2mb\r")).toEqual([]);
    const ab = [{ text: "a", style: {} }, { text: "b", style: { fg: 2 } }];
    expect(p.pending()?.spans).toEqual(ab);
    expect(p.push("\nc")).toEqual([{ spans: ab, truncated: false }]);
    expect(p.pending()?.spans).toEqual([{ text: "c", style: { fg: 2 } }]);
    expect(p.end()?.spans).toEqual([{ text: "c", style: { fg: 2 } }]);
    expect(p.pending()).toBeNull();
  });

  it("carries the style across lines and resets cleanly", () => {
    const p = new AnsiParser();
    const lines = p.push("\x1b[31ma\nb\n");
    expect(lines.map((l) => l.spans[0]?.style)).toEqual([{ fg: 1 }, { fg: 1 }]);
    p.reset();
    expect(p.push("c\n")[0]?.spans[0]?.style).toEqual({});
  });
});

describe("run helpers", () => {
  it("labels and classifies statuses", () => {
    expect(statusLabel("awaiting_approval")).toBe("Awaiting approval");
    expect(isFinishedStatus("succeeded")).toBe(true);
    expect(isFinishedStatus("skipped")).toBe(true);
    expect(isFinishedStatus("running")).toBe(false);
    expect(isWaitingJob("queued")).toBe(true);
    expect(isWaitingJob("running")).toBe(false);
  });

  it("neutralizes controls and bidi overrides in untrusted text", () => {
    expect(displayText("\u202Eniam")).toBe("\ufffdniam");
    expect(displayText("a\x1b[31mb\x00c\u2066")).toBe("a\ufffd[31mb\ufffdc\ufffd");
    expect(displayText("feature/日本 ✓")).toBe("feature/日本 ✓");
  });

  it("formats durations", () => {
    const now = new Date("2026-01-01T01:00:00Z");
    expect(formatDuration(null, null, now)).toBe("");
    expect(formatDuration("2026-01-01T00:59:55Z", null, now)).toBe("5s");
    expect(formatDuration("2026-01-01T00:00:00Z", "2026-01-01T00:01:05Z")).toBe("1m 05s");
    expect(formatDuration("2026-01-01T00:00:00Z", "2026-01-01T02:03:00Z")).toBe("2h 03m");
    expect(formatDuration("bad", null, now)).toBe("");
    expect(shortSha("0123456789abcdef")).toBe("0123456");
  });
});

describe("LogBuffer", () => {
  it("decodes UTF-8 split across chunks", () => {
    const b = new LogBuffer();
    const bytes = new TextEncoder().encode("✓ ok\n");
    b.pushBytes(bytes.slice(0, 1));
    b.pushBytes(bytes.slice(1));
    expect(texts(b.lines)).toEqual(["✓ ok"]);
    b.pushBytes(new Uint8Array([0xff, 0x0a]));
    expect(texts(b.lines)).toEqual(["✓ ok", "�"]);
  });

  it("keeps only the most recent lines and counts the rest", () => {
    const b = new LogBuffer({ maxLines: 100 });
    b.pushText(Array.from({ length: 250 }, (_, i) => `line ${String(i)}\n`).join(""));
    expect(b.lines.length).toBeLessThanOrEqual(110);
    expect(b.dropped + b.lines.length).toBe(250);
    expect(texts(b.lines).at(-1)).toBe("line 249");
    const small = new LogBuffer({ maxLines: 2 });
    small.pushText("a\nb\nc\n");
    expect(texts(small.lines)).toEqual(["b", "c"]);
    expect(small.dropped).toBe(1);
  });

  it("keeps within a character budget", () => {
    const b = new LogBuffer({ maxChars: 1000 });
    b.pushText(`${"y".repeat(99)}\n`.repeat(50));
    const total = b.lines.reduce((n, l) => n + (l.spans[0]?.text.length ?? 0), 0);
    expect(total).toBeLessThanOrEqual(1000);
    expect(b.dropped).toBeGreaterThan(0);
    expect(b.dropped + b.lines.length).toBe(50);
  });

  it("exposes the pending line and resets", () => {
    const b = new LogBuffer({ maxLineChars: 3 });
    b.pushText("abcdef");
    expect(b.pending()).toEqual({ spans: [{ text: "abc", style: {} }], truncated: true });
    b.reset();
    expect(b.pending()).toBeNull();
    expect(b.lines).toEqual([]);
    expect(b.dropped).toBe(0);
  });
});
