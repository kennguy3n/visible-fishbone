//! Optical character recognition for the DLP inspection pipeline.
//!
//! ## Why this exists
//!
//! The classifier only ever saw *text*. A credit-card number pasted into a
//! screenshot, or an API key in a cropped image attachment, was invisible to
//! every detector. This module closes that gap: it turns a bounded class of
//! images into UTF-8 text that the existing detectors then scan unchanged.
//!
//! ## Honest scope
//!
//! This is **not** a general scene-text recogniser. It targets *crisp,
//! fixed-pitch bitmap/monospace text on a near-uniform background* — exactly
//! what screenshots of terminals, logs, spreadsheets and chat windows look
//! like, which is where leaked secrets overwhelmingly appear. The pipeline is:
//!
//! 1. **decode** ([`decode`]) — PNG (via the `png` crate) plus in-crate BMP and
//!    Netpbm readers, all converted to 8-bit luma.
//! 2. **binarize** — global [Otsu] threshold (computed in integer arithmetic).
//! 3. **segment** — horizontal projection into text lines; per line, the glyph
//!    pitch is recovered from the line height and the grid phase is found by
//!    minimising ink in the inter-glyph gap columns.
//! 4. **recognise** — each fixed-pitch cell is resampled to the native 5x7 cell
//!    and matched against the embedded [`font`] templates by Hamming distance.
//!
//! Anything outside the documented charset, or any input that breaches a cap,
//! is skipped gracefully — the pipeline never panics and never blocks.
//!
//! ## No-ops cost model (5 000-tenant SaaS)
//!
//! Every stage is bounded *before* it runs: input bytes, per-side dimension,
//! total pixels, recognised-glyph count, output characters, and a wall-clock
//! budget. Worst case is `O(pixels)` for decode/binarize/segment plus
//! `O(glyphs × templates)` for matching, both hard-capped, so a single item can
//! never exceed a few hundred milliseconds or a few megabytes regardless of
//! input. Non-image content is rejected by a cheap magic-byte sniff, so the
//! text hot path pays nothing.
//!
//! [Otsu]: https://en.wikipedia.org/wiki/Otsu%27s_method

use std::time::{Duration, Instant};

mod decode;
mod font;
#[cfg(test)]
mod render;
#[cfg(test)]
mod tests;

use decode::{DecodeError, GrayImage};
use font::{GLYPH_H, GLYPH_W};

/// Bounds applied to every OCR invocation. Defaults are tuned for unattended,
/// multi-tenant operation: generous enough for real screenshots, tight enough
/// that no single item can monopolise CPU or memory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OcrLimits {
    /// Maximum encoded image size accepted before decoding is attempted.
    pub max_input_bytes: usize,
    /// Maximum width or height, in pixels, of the decoded raster.
    pub max_dimension: usize,
    /// Maximum total pixel count of the decoded raster.
    pub max_pixels: usize,
    /// Maximum number of glyph cells recognised across the whole image.
    pub max_glyphs: usize,
    /// Maximum number of UTF-8 characters returned.
    pub max_output_chars: usize,
    /// Wall-clock budget for the recognition phase.
    pub time_budget: Duration,
}

impl Default for OcrLimits {
    fn default() -> Self {
        Self {
            max_input_bytes: 4 * 1024 * 1024,
            max_dimension: 4096,
            max_pixels: 4_000_000,
            max_glyphs: 20_000,
            max_output_chars: 20_000,
            time_budget: Duration::from_millis(250),
        }
    }
}

/// Why an image produced no usable text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OcrSkip {
    /// Magic bytes matched no supported decoder (the common, cheap case).
    UnsupportedFormat,
    /// Input bytes or decoded dimensions exceeded a cap.
    TooLarge,
    /// A supported format failed to decode (truncated/corrupt).
    DecodeFailed,
    /// Decoding succeeded but no glyph cleared the recognition threshold.
    NoText,
    /// The recognition phase ran out of its wall-clock budget before any text
    /// was produced.
    TimeBudgetExceeded,
}

/// Outcome of an OCR attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OcrOutcome {
    /// Text was recovered. `glyphs` is the number of cells recognised, useful
    /// for telemetry and for proving the cap was respected.
    Extracted { text: String, glyphs: usize },
    /// Nothing usable was produced; carries the reason.
    Skipped(OcrSkip),
}

/// Maximum Hamming distance (out of the 35 cell bits) for a glyph match to be
/// accepted. Above this the cell is treated as noise and dropped, which keeps
/// non-text imagery from injecting garbage into the detectors.
const MAX_HAMMING: u32 = 6;

/// Extract text from `content` under explicit `limits`.
///
/// Returns [`OcrOutcome::Skipped`] (never an error and never a panic) for
/// non-images, oversized inputs, decode failures, and blank images, so callers
/// can treat OCR as a best-effort, fail-open enrichment step.
#[must_use]
pub fn extract_image_text(content: &[u8], limits: &OcrLimits) -> OcrOutcome {
    if content.len() > limits.max_input_bytes {
        return OcrOutcome::Skipped(OcrSkip::TooLarge);
    }
    let image = match decode::decode(content, limits.max_dimension, limits.max_pixels) {
        Ok(image) => image,
        Err(DecodeError::Unsupported) => return OcrOutcome::Skipped(OcrSkip::UnsupportedFormat),
        Err(DecodeError::Oversized) => return OcrOutcome::Skipped(OcrSkip::TooLarge),
        Err(DecodeError::Malformed) => return OcrOutcome::Skipped(OcrSkip::DecodeFailed),
    };

    let started = Instant::now();
    let threshold = otsu_threshold(&image);
    let mut output = String::new();
    let mut glyphs = 0usize;

    for band in find_line_bands(&image, threshold) {
        if started.elapsed() > limits.time_budget {
            if output.trim().is_empty() {
                return OcrOutcome::Skipped(OcrSkip::TimeBudgetExceeded);
            }
            break;
        }
        let line = recognize_line(&image, threshold, band, &mut glyphs, limits);
        if !line.is_empty() {
            if !output.is_empty() {
                output.push('\n');
            }
            output.push_str(&line);
        }
        if glyphs >= limits.max_glyphs || output.chars().count() >= limits.max_output_chars {
            break;
        }
    }

    truncate_chars(&mut output, limits.max_output_chars);
    let trimmed = output.trim();
    if trimmed.is_empty() {
        OcrOutcome::Skipped(OcrSkip::NoText)
    } else {
        OcrOutcome::Extracted {
            text: trimmed.to_owned(),
            glyphs,
        }
    }
}

/// Convenience wrapper for the detection hot path: returns the extracted text
/// only when something non-empty was recovered, using [`OcrLimits::default`].
/// This is the single entry point the engine calls before classification.
#[must_use]
pub fn extract_text_for_detection(content: &[u8]) -> Option<String> {
    match extract_image_text(content, &OcrLimits::default()) {
        OcrOutcome::Extracted { text, .. } if !text.trim().is_empty() => Some(text),
        _ => None,
    }
}

/// A vertical run of rows `[top, bottom)` containing a single text line.
#[derive(Clone, Copy, Debug)]
struct LineBand {
    top: usize,
    bottom: usize,
}

fn ink(image: &GrayImage, threshold: u8, x: usize, y: usize) -> bool {
    // Otsu accumulates the "back" class as luma values `<= t`, so the dark (ink)
    // class is `luma <= threshold`. For a perfectly bimodal screenshot the
    // optimal split lands at `t = 0`, and ink pixels sit exactly at luma 0 — a
    // strict `<` would miss them and the whole image would read as blank.
    image
        .luma
        .get(y * image.width + x)
        .is_some_and(|&l| l <= threshold)
}

/// Integer-arithmetic Otsu threshold. Returns the luma value `t` such that
/// pixels with `luma <= t` are treated as ink (see [`ink`]).
fn otsu_threshold(image: &GrayImage) -> u8 {
    let mut hist = [0u64; 256];
    for &l in &image.luma {
        hist[l as usize] += 1;
    }
    let total: u64 = image.luma.len() as u64;
    if total == 0 {
        return 0;
    }
    let sum_total: u64 = hist.iter().enumerate().map(|(i, &c)| i as u64 * c).sum();

    let mut weight_back: u64 = 0;
    let mut sum_back: u64 = 0;
    let mut best_num_sq: u128 = 0;
    let mut best_den: u128 = 1;
    let mut threshold = 0usize;
    let mut found = false;

    for (t, &count) in hist.iter().enumerate() {
        weight_back += count;
        if weight_back == 0 {
            continue;
        }
        let weight_fore = total - weight_back;
        if weight_fore == 0 {
            break;
        }
        sum_back += t as u64 * count;
        let sum_fore = sum_total - sum_back;
        // Between-class variance is `wB*wF*(mB-mF)^2`; comparing the exact
        // fraction `num^2 / (wB*wF)` via cross-multiplication keeps the whole
        // computation in integers (no float casts on the decode path).
        let num: i128 = i128::from(sum_back) * i128::from(weight_fore)
            - i128::from(sum_fore) * i128::from(weight_back);
        let num_abs = num.unsigned_abs();
        let num_sq = num_abs * num_abs;
        let den = u128::from(weight_back) * u128::from(weight_fore);
        if !found || num_sq * best_den > best_num_sq * den {
            best_num_sq = num_sq;
            best_den = den;
            threshold = t;
            found = true;
        }
    }
    u8::try_from(threshold).unwrap_or(0)
}

/// Split the image into text lines by horizontal projection: maximal runs of
/// rows that contain at least one ink pixel.
fn find_line_bands(image: &GrayImage, threshold: u8) -> Vec<LineBand> {
    let row_has_ink = |y: usize| (0..image.width).any(|x| ink(image, threshold, x, y));
    let mut bands = Vec::new();
    let mut y = 0;
    while y < image.height {
        while y < image.height && !row_has_ink(y) {
            y += 1;
        }
        if y >= image.height {
            break;
        }
        let top = y;
        while y < image.height && row_has_ink(y) {
            y += 1;
        }
        bands.push(LineBand { top, bottom: y });
    }
    bands
}

/// Recognise a single line band into a string, appending to `glyphs` the number
/// of content cells inspected so the global cap can be enforced.
fn recognize_line(
    image: &GrayImage,
    threshold: u8,
    band: LineBand,
    glyphs: &mut usize,
    limits: &OcrLimits,
) -> String {
    let band_h = band.bottom.saturating_sub(band.top);
    if band_h == 0 {
        return String::new();
    }
    // Pitch is recovered from the line height: a full cell is GLYPH_H rows tall.
    let scale = ((band_h + GLYPH_H / 2) / GLYPH_H).max(1);
    let cell_w = GLYPH_W * scale;
    let period = cell_w + scale; // one blank column-group between cells

    // Column ink counts within the band drive both phase recovery and the
    // blank-cell (space) test.
    let mut col_ink = vec![0u32; image.width];
    let mut first_active = None;
    let mut last_active = 0usize;
    for (x, slot) in col_ink.iter_mut().enumerate() {
        let mut count = 0u32;
        for y in band.top..band.bottom {
            if ink(image, threshold, x, y) {
                count += 1;
            }
        }
        *slot = count;
        if count > 0 {
            first_active.get_or_insert(x);
            last_active = x;
        }
    }
    if first_active.is_none() {
        return String::new();
    }
    let x1 = last_active;

    // Cells start at `phase + k*period`; because every column left of the first
    // ink is blank, the chosen phase always lands a cell boundary on the first
    // glyph, so this all-`usize` walk needs no signed offset.
    let phase = best_phase(&col_ink, x1, period, cell_w);

    let mut line = String::new();
    let mut pending_space = false;
    let mut cell_start = phase;
    while cell_start <= x1 && cell_start < image.width {
        let start = cell_start;
        let end = (start + cell_w).min(image.width);
        cell_start += period;
        let cell_ink: u32 = col_ink.get(start..end).map_or(0, |s| s.iter().sum());
        if cell_ink == 0 {
            if !line.is_empty() {
                pending_space = true;
            }
            continue;
        }
        *glyphs += 1;
        if *glyphs > limits.max_glyphs {
            break;
        }
        let sample = resample_cell(image, threshold, start, band.top, end - start, band_h);
        if let Some(ch) = match_glyph(sample) {
            if pending_space && !line.is_empty() {
                line.push(' ');
            }
            pending_space = false;
            line.push(ch);
        }
    }
    line
}

/// Find the grid phase `p ∈ [0, period)` that places the inter-cell gap columns
/// over the least ink — i.e. aligns the fixed-pitch grid to the glyphs. Cells
/// are anchored at `p + k*period`, so every position stays non-negative.
fn best_phase(col_ink: &[u32], x1: usize, period: usize, cell_w: usize) -> usize {
    let mut best_phase = 0usize;
    let mut best_penalty = u64::MAX;
    for phase in 0..period {
        let mut penalty = 0u64;
        let mut cell_start = phase;
        while cell_start <= x1 {
            let gap_start = cell_start + cell_w;
            let gap_end = cell_start + period;
            if let Some(gap) = col_ink.get(gap_start..gap_end.min(col_ink.len())) {
                penalty += gap.iter().map(|&c| u64::from(c)).sum::<u64>();
            }
            cell_start += period;
        }
        if penalty < best_penalty {
            best_penalty = penalty;
            best_phase = phase;
        }
    }
    best_phase
}

/// Resample a cell region to the native 5x7 grid, returning the packed 35-bit
/// glyph mask (same bit layout as [`font::Glyph::bits`]).
fn resample_cell(
    image: &GrayImage,
    threshold: u8,
    sx0: usize,
    sy0: usize,
    sw: usize,
    sh: usize,
) -> u64 {
    let mut acc: u64 = 0;
    for ty in 0..GLYPH_H {
        let by0 = sy0 + ty * sh / GLYPH_H;
        let by1 = (sy0 + (ty + 1) * sh / GLYPH_H).max(by0 + 1);
        let mut row_bits: u64 = 0;
        for tx in 0..GLYPH_W {
            let bx0 = sx0 + tx * sw / GLYPH_W;
            let bx1 = (sx0 + (tx + 1) * sw / GLYPH_W).max(bx0 + 1);
            let mut total = 0u32;
            let mut inked = 0u32;
            for y in by0..by1 {
                for x in bx0..bx1 {
                    total += 1;
                    if ink(image, threshold, x, y) {
                        inked += 1;
                    }
                }
            }
            // Majority vote, ties counting as ink so thin strokes survive.
            if total > 0 && inked * 2 >= total {
                row_bits |= 1 << (GLYPH_W - 1 - tx);
            }
        }
        acc = (acc << GLYPH_W) | row_bits;
    }
    acc
}

/// Match a resampled cell against the font templates, returning the closest
/// character within [`MAX_HAMMING`], or `None` if the cell looks like noise.
fn match_glyph(sample: u64) -> Option<char> {
    let mut best: Option<(u32, char)> = None;
    for glyph in font::GLYPHS {
        let distance = (sample ^ glyph.bits()).count_ones();
        if best.is_none_or(|(d, _)| distance < d) {
            best = Some((distance, glyph.ch));
        }
    }
    match best {
        Some((distance, ch)) if distance <= MAX_HAMMING => Some(ch),
        _ => None,
    }
}

/// Truncate `text` to at most `max_chars` characters on a char boundary.
fn truncate_chars(text: &mut String, max_chars: usize) {
    if text.chars().count() <= max_chars {
        return;
    }
    let end = text
        .char_indices()
        .nth(max_chars)
        .map_or(text.len(), |(idx, _)| idx);
    text.truncate(end);
}
