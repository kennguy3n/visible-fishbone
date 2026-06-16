//! Clean-room 5x7 monospace bitmap font used by the OCR engine.
//!
//! The same glyph templates serve two purposes:
//!
//! * **Recognition** — each segmented glyph box is resampled to the native
//!   5x7 cell and matched against these templates by Hamming distance over the
//!   35 cell bits (`glyph_bits`).
//! * **Fixture rendering** — [`render_line`] draws a string using the identical
//!   templates so tests can synthesise crisp screenshots that the recogniser
//!   then reads back. This is what makes the OCR path testable end-to-end
//!   without shipping a binary image fixture.
//!
//! The bitmaps are authored by hand (no third-party font data) as a legible
//! LED-style 5x7 face covering the documented charset: space, the ten digits,
//! `A`–`Z`, `a`–`z`, and the separators `. , - _ : / @ + #`. Anything outside
//! that set is rendered/segmented as a blank cell and skipped on recognition.

/// Glyph cell width in pixels (columns).
pub(crate) const GLYPH_W: usize = 5;
/// Glyph cell height in pixels (rows).
pub(crate) const GLYPH_H: usize = 7;

/// A single bitmap glyph. Each `rows` entry holds the five cell columns in its
/// low bits, with bit `GLYPH_W - 1` (`0b1_0000`) the leftmost column.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Glyph {
    pub ch: char,
    pub rows: [u8; GLYPH_H],
}

impl Glyph {
    /// Pack the glyph into a 35-bit mask (row-major, MSB-first within a row) for
    /// constant-time Hamming comparison against a resampled sample.
    pub(crate) fn bits(&self) -> u64 {
        let mut acc: u64 = 0;
        for &row in &self.rows {
            acc = (acc << GLYPH_W) | u64::from(row & 0b1_1111);
        }
        acc
    }
}

/// The full template table. Order is irrelevant to correctness; a unit test
/// asserts every bitmap is pairwise distinct so recognition is unambiguous.
pub(crate) const GLYPHS: &[Glyph] = &[
    // digits
    Glyph {
        ch: '0',
        rows: [
            0b01110, 0b10001, 0b10011, 0b10101, 0b11001, 0b10001, 0b01110,
        ],
    },
    Glyph {
        ch: '1',
        rows: [
            0b00100, 0b01100, 0b00100, 0b00100, 0b00100, 0b00100, 0b01110,
        ],
    },
    Glyph {
        ch: '2',
        rows: [
            0b01110, 0b10001, 0b00001, 0b00010, 0b00100, 0b01000, 0b11111,
        ],
    },
    Glyph {
        ch: '3',
        rows: [
            0b11111, 0b00010, 0b00100, 0b00010, 0b00001, 0b10001, 0b01110,
        ],
    },
    Glyph {
        ch: '4',
        rows: [
            0b00010, 0b00110, 0b01010, 0b10010, 0b11111, 0b00010, 0b00010,
        ],
    },
    Glyph {
        ch: '5',
        rows: [
            0b11111, 0b10000, 0b11110, 0b00001, 0b00001, 0b10001, 0b01110,
        ],
    },
    Glyph {
        ch: '6',
        rows: [
            0b00110, 0b01000, 0b10000, 0b11110, 0b10001, 0b10001, 0b01110,
        ],
    },
    Glyph {
        ch: '7',
        rows: [
            0b11111, 0b00001, 0b00010, 0b00100, 0b01000, 0b01000, 0b01000,
        ],
    },
    Glyph {
        ch: '8',
        rows: [
            0b01110, 0b10001, 0b10001, 0b01110, 0b10001, 0b10001, 0b01110,
        ],
    },
    Glyph {
        ch: '9',
        rows: [
            0b01110, 0b10001, 0b10001, 0b01111, 0b00001, 0b00010, 0b01100,
        ],
    },
    // uppercase
    Glyph {
        ch: 'A',
        rows: [
            0b01110, 0b10001, 0b10001, 0b11111, 0b10001, 0b10001, 0b10001,
        ],
    },
    Glyph {
        ch: 'B',
        rows: [
            0b11110, 0b10001, 0b10001, 0b11110, 0b10001, 0b10001, 0b11110,
        ],
    },
    Glyph {
        ch: 'C',
        rows: [
            0b01110, 0b10001, 0b10000, 0b10000, 0b10000, 0b10001, 0b01110,
        ],
    },
    Glyph {
        ch: 'D',
        rows: [
            0b11100, 0b10010, 0b10001, 0b10001, 0b10001, 0b10010, 0b11100,
        ],
    },
    Glyph {
        ch: 'E',
        rows: [
            0b11111, 0b10000, 0b10000, 0b11110, 0b10000, 0b10000, 0b11111,
        ],
    },
    Glyph {
        ch: 'F',
        rows: [
            0b11111, 0b10000, 0b10000, 0b11110, 0b10000, 0b10000, 0b10000,
        ],
    },
    Glyph {
        ch: 'G',
        rows: [
            0b01110, 0b10001, 0b10000, 0b10111, 0b10001, 0b10001, 0b01111,
        ],
    },
    Glyph {
        ch: 'H',
        rows: [
            0b10001, 0b10001, 0b10001, 0b11111, 0b10001, 0b10001, 0b10001,
        ],
    },
    Glyph {
        ch: 'I',
        rows: [
            0b01110, 0b00100, 0b00100, 0b00100, 0b00100, 0b00100, 0b01110,
        ],
    },
    Glyph {
        ch: 'J',
        rows: [
            0b00111, 0b00010, 0b00010, 0b00010, 0b00010, 0b10010, 0b01100,
        ],
    },
    Glyph {
        ch: 'K',
        rows: [
            0b10001, 0b10010, 0b10100, 0b11000, 0b10100, 0b10010, 0b10001,
        ],
    },
    Glyph {
        ch: 'L',
        rows: [
            0b10000, 0b10000, 0b10000, 0b10000, 0b10000, 0b10000, 0b11111,
        ],
    },
    Glyph {
        ch: 'M',
        rows: [
            0b10001, 0b11011, 0b10101, 0b10101, 0b10001, 0b10001, 0b10001,
        ],
    },
    Glyph {
        ch: 'N',
        rows: [
            0b10001, 0b11001, 0b10101, 0b10011, 0b10001, 0b10001, 0b10001,
        ],
    },
    Glyph {
        ch: 'O',
        rows: [
            0b01110, 0b10001, 0b10001, 0b10001, 0b10001, 0b10001, 0b01110,
        ],
    },
    Glyph {
        ch: 'P',
        rows: [
            0b11110, 0b10001, 0b10001, 0b11110, 0b10000, 0b10000, 0b10000,
        ],
    },
    Glyph {
        ch: 'Q',
        rows: [
            0b01110, 0b10001, 0b10001, 0b10001, 0b10101, 0b10010, 0b01101,
        ],
    },
    Glyph {
        ch: 'R',
        rows: [
            0b11110, 0b10001, 0b10001, 0b11110, 0b10100, 0b10010, 0b10001,
        ],
    },
    Glyph {
        ch: 'S',
        rows: [
            0b01111, 0b10000, 0b10000, 0b01110, 0b00001, 0b00001, 0b11110,
        ],
    },
    Glyph {
        ch: 'T',
        rows: [
            0b11111, 0b00100, 0b00100, 0b00100, 0b00100, 0b00100, 0b00100,
        ],
    },
    Glyph {
        ch: 'U',
        rows: [
            0b10001, 0b10001, 0b10001, 0b10001, 0b10001, 0b10001, 0b01110,
        ],
    },
    Glyph {
        ch: 'V',
        rows: [
            0b10001, 0b10001, 0b10001, 0b10001, 0b10001, 0b01010, 0b00100,
        ],
    },
    Glyph {
        ch: 'W',
        rows: [
            0b10001, 0b10001, 0b10001, 0b10101, 0b10101, 0b10101, 0b01010,
        ],
    },
    Glyph {
        ch: 'X',
        rows: [
            0b10001, 0b10001, 0b01010, 0b00100, 0b01010, 0b10001, 0b10001,
        ],
    },
    Glyph {
        ch: 'Y',
        rows: [
            0b10001, 0b10001, 0b01010, 0b00100, 0b00100, 0b00100, 0b00100,
        ],
    },
    Glyph {
        ch: 'Z',
        rows: [
            0b11111, 0b00001, 0b00010, 0b00100, 0b01000, 0b10000, 0b11111,
        ],
    },
    // lowercase
    Glyph {
        ch: 'a',
        rows: [
            0b00000, 0b00000, 0b01110, 0b00001, 0b01111, 0b10001, 0b01111,
        ],
    },
    Glyph {
        ch: 'b',
        rows: [
            0b10000, 0b10000, 0b11110, 0b10001, 0b10001, 0b10001, 0b11110,
        ],
    },
    Glyph {
        ch: 'c',
        rows: [
            0b00000, 0b00000, 0b01111, 0b10000, 0b10000, 0b10000, 0b01111,
        ],
    },
    Glyph {
        ch: 'd',
        rows: [
            0b00001, 0b00001, 0b01111, 0b10001, 0b10001, 0b10001, 0b01111,
        ],
    },
    Glyph {
        ch: 'e',
        rows: [
            0b00000, 0b00000, 0b01110, 0b10001, 0b11111, 0b10000, 0b01110,
        ],
    },
    Glyph {
        ch: 'f',
        rows: [
            0b00110, 0b01001, 0b01000, 0b11110, 0b01000, 0b01000, 0b01000,
        ],
    },
    Glyph {
        ch: 'g',
        rows: [
            0b00000, 0b01111, 0b10001, 0b10001, 0b01111, 0b00001, 0b01110,
        ],
    },
    Glyph {
        ch: 'h',
        rows: [
            0b10000, 0b10000, 0b11110, 0b10001, 0b10001, 0b10001, 0b10001,
        ],
    },
    Glyph {
        ch: 'i',
        rows: [
            0b00100, 0b00000, 0b01100, 0b00100, 0b00100, 0b00100, 0b01110,
        ],
    },
    Glyph {
        ch: 'j',
        rows: [
            0b00010, 0b00000, 0b00110, 0b00010, 0b00010, 0b10010, 0b01100,
        ],
    },
    Glyph {
        ch: 'k',
        rows: [
            0b10000, 0b10000, 0b10010, 0b10100, 0b11000, 0b10100, 0b10010,
        ],
    },
    Glyph {
        ch: 'l',
        rows: [
            0b01100, 0b00100, 0b00100, 0b00100, 0b00100, 0b00100, 0b01110,
        ],
    },
    Glyph {
        ch: 'm',
        rows: [
            0b00000, 0b00000, 0b11010, 0b10101, 0b10101, 0b10101, 0b10101,
        ],
    },
    Glyph {
        ch: 'n',
        rows: [
            0b00000, 0b00000, 0b11110, 0b10001, 0b10001, 0b10001, 0b10001,
        ],
    },
    Glyph {
        ch: 'o',
        rows: [
            0b00000, 0b00000, 0b01110, 0b10001, 0b10001, 0b10001, 0b01110,
        ],
    },
    Glyph {
        ch: 'p',
        rows: [
            0b00000, 0b11110, 0b10001, 0b10001, 0b11110, 0b10000, 0b10000,
        ],
    },
    Glyph {
        ch: 'q',
        rows: [
            0b00000, 0b01111, 0b10001, 0b10001, 0b01111, 0b00001, 0b00001,
        ],
    },
    Glyph {
        ch: 'r',
        rows: [
            0b00000, 0b00000, 0b10110, 0b11001, 0b10000, 0b10000, 0b10000,
        ],
    },
    Glyph {
        ch: 's',
        rows: [
            0b00000, 0b00000, 0b01111, 0b10000, 0b01110, 0b00001, 0b11110,
        ],
    },
    Glyph {
        ch: 't',
        rows: [
            0b01000, 0b01000, 0b11110, 0b01000, 0b01000, 0b01001, 0b00110,
        ],
    },
    Glyph {
        ch: 'u',
        rows: [
            0b00000, 0b00000, 0b10001, 0b10001, 0b10001, 0b10011, 0b01101,
        ],
    },
    Glyph {
        ch: 'v',
        rows: [
            0b00000, 0b00000, 0b10001, 0b10001, 0b10001, 0b01010, 0b00100,
        ],
    },
    Glyph {
        ch: 'w',
        rows: [
            0b00000, 0b00000, 0b10001, 0b10001, 0b10101, 0b10101, 0b01010,
        ],
    },
    Glyph {
        ch: 'x',
        rows: [
            0b00000, 0b00000, 0b10001, 0b01010, 0b00100, 0b01010, 0b10001,
        ],
    },
    Glyph {
        ch: 'y',
        rows: [
            0b00000, 0b10001, 0b10001, 0b10001, 0b01111, 0b00001, 0b01110,
        ],
    },
    Glyph {
        ch: 'z',
        rows: [
            0b00000, 0b00000, 0b11111, 0b00010, 0b00100, 0b01000, 0b11111,
        ],
    },
    // punctuation / separators
    Glyph {
        ch: '.',
        rows: [
            0b00000, 0b00000, 0b00000, 0b00000, 0b00000, 0b01100, 0b01100,
        ],
    },
    Glyph {
        ch: ',',
        rows: [
            0b00000, 0b00000, 0b00000, 0b00000, 0b00000, 0b00100, 0b01000,
        ],
    },
    Glyph {
        ch: '-',
        rows: [
            0b00000, 0b00000, 0b00000, 0b11111, 0b00000, 0b00000, 0b00000,
        ],
    },
    Glyph {
        ch: '_',
        rows: [
            0b00000, 0b00000, 0b00000, 0b00000, 0b00000, 0b00000, 0b11111,
        ],
    },
    Glyph {
        ch: ':',
        rows: [
            0b00000, 0b01100, 0b01100, 0b00000, 0b01100, 0b01100, 0b00000,
        ],
    },
    Glyph {
        ch: '/',
        rows: [
            0b00001, 0b00010, 0b00100, 0b00100, 0b00100, 0b01000, 0b10000,
        ],
    },
    Glyph {
        ch: '@',
        rows: [
            0b01110, 0b10001, 0b10111, 0b10101, 0b10111, 0b10000, 0b01110,
        ],
    },
    Glyph {
        ch: '+',
        rows: [
            0b00000, 0b00100, 0b00100, 0b11111, 0b00100, 0b00100, 0b00000,
        ],
    },
    Glyph {
        ch: '#',
        rows: [
            0b01010, 0b01010, 0b11111, 0b01010, 0b11111, 0b01010, 0b01010,
        ],
    },
];

/// Look up the template for `ch`, if it is in the supported charset.
///
/// Only the test-only renderer needs glyph lookup by character; the recogniser
/// works the other way (sampled bitmap → nearest glyph) via [`GLYPHS`].
#[cfg(test)]
pub(crate) fn lookup(ch: char) -> Option<&'static Glyph> {
    GLYPHS.iter().find(|g| g.ch == ch)
}
