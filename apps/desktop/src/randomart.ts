/**
 * Safety-number randomart — the OpenSSH "drunken bishop" walk, applied to a
 * DRIFT safety number. Visualization only, not cryptography: both peers feed
 * the identical safety-number string through the identical deterministic walk,
 * so identical keys give an identical picture and a mismatch is visible at a
 * glance instead of read digit-by-digit.
 */

const WIDTH = 17;
const HEIGHT = 9;
// Same coin flavor as OpenSSH: frequency ramp, S = start, E = end.
const SYMBOLS = " .o+=*BOX@%&#/^";

export function randomart(input: string): string {
  const field: number[] = new Array(WIDTH * HEIGHT).fill(0);
  let x = Math.floor(WIDTH / 2);
  let y = Math.floor(HEIGHT / 2);
  const start = y * WIDTH + x;

  for (let i = 0; i < input.length; i++) {
    let byte = input.charCodeAt(i);
    for (let b = 0; b < 4; b++) {
      // two bits per move: 00 ↖  01 ↗  10 ↙  11 ↘
      x += (byte & 1) === 0 ? -1 : 1;
      y += (byte & 2) === 0 ? -1 : 1;
      x = Math.max(0, Math.min(WIDTH - 1, x));
      y = Math.max(0, Math.min(HEIGHT - 1, y));
      const idx = y * WIDTH + x;
      if (field[idx] < SYMBOLS.length - 1) field[idx]++;
      byte >>= 2;
    }
  }
  const end = y * WIDTH + x;

  const rows: string[] = ["+" + "-".repeat(WIDTH) + "+"];
  for (let r = 0; r < HEIGHT; r++) {
    let row = "|";
    for (let c = 0; c < WIDTH; c++) {
      const idx = r * WIDTH + c;
      if (idx === start) row += "S";
      else if (idx === end) row += "E";
      else row += SYMBOLS[field[idx]];
    }
    rows.push(row + "|");
  }
  rows.push("+" + "-".repeat(WIDTH) + "+");
  return rows.join("\n");
}
