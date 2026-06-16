//! Tests for the OCR engine: round-trip recognition of rendered text, decoder
//! coverage for the in-crate BMP/Netpbm parsers, cap enforcement, and the
//! end-to-end "secret in a screenshot is now detected" guarantee.

use super::render::{render_line_png, render_lines_png};
use super::*;
use crate::channels::DlpChannel;
use crate::classifier::{ContentClassifier, ContentMetadata};
use crate::rules::{DlpRule, PatternType, RuleAction, Severity};
use pretty_assertions::assert_eq;

fn extract(content: &[u8]) -> OcrOutcome {
    extract_image_text(content, &OcrLimits::default())
}

fn text_of(outcome: OcrOutcome) -> String {
    match outcome {
        OcrOutcome::Extracted { text, .. } => text,
        OcrOutcome::Skipped(skip) => panic!("expected extracted text, skipped: {skip:?}"),
    }
}

#[test]
fn reads_back_plain_digits() {
    let png = render_line_png("4111111111111111", 2);
    assert_eq!(text_of(extract(&png)), "4111111111111111");
}

#[test]
fn reads_back_digit_groups_with_spaces() {
    let png = render_line_png("4111 1111 1111 1111", 3);
    assert_eq!(text_of(extract(&png)), "4111 1111 1111 1111");
}

#[test]
fn reads_back_mixed_case_letters_and_punctuation() {
    let png = render_line_png("Order-ID: AB~", 2); // '~' is an unsupported glyph
    // The unsupported character is rendered as a blank cell and dropped, the
    // rest must survive verbatim.
    assert_eq!(text_of(extract(&png)), "Order-ID: AB");
}

#[test]
fn reads_back_multiple_lines() {
    let png = render_lines_png(&["Name: John", "SSN 078-05-1120"], 2);
    assert_eq!(text_of(extract(&png)), "Name: John\nSSN 078-05-1120");
}

#[test]
fn font_templates_are_pairwise_distinct() {
    // A typo that made two glyphs identical would silently corrupt recognition;
    // this guards the hand-authored table.
    let glyphs = font::GLYPHS;
    for (i, a) in glyphs.iter().enumerate() {
        for b in &glyphs[i + 1..] {
            assert!(
                a.bits() != b.bits(),
                "glyphs {:?} and {:?} have identical bitmaps",
                a.ch,
                b.ch
            );
        }
    }
}

#[test]
fn unsupported_format_is_skipped_cheaply() {
    assert_eq!(
        extract(b"%PDF-1.7\n%..."),
        OcrOutcome::Skipped(OcrSkip::UnsupportedFormat)
    );
    assert_eq!(
        extract(b"not an image at all"),
        OcrOutcome::Skipped(OcrSkip::UnsupportedFormat)
    );
    assert_eq!(
        extract(&[]),
        OcrOutcome::Skipped(OcrSkip::UnsupportedFormat)
    );
}

#[test]
fn oversized_input_bytes_are_skipped() {
    let png = render_line_png("12345", 2);
    let limits = OcrLimits {
        max_input_bytes: 8,
        ..OcrLimits::default()
    };
    assert_eq!(
        extract_image_text(&png, &limits),
        OcrOutcome::Skipped(OcrSkip::TooLarge)
    );
}

#[test]
fn oversized_dimensions_are_skipped() {
    let png = render_line_png("12345", 4);
    let limits = OcrLimits {
        max_pixels: 16,
        ..OcrLimits::default()
    };
    assert_eq!(
        extract_image_text(&png, &limits),
        OcrOutcome::Skipped(OcrSkip::TooLarge)
    );
}

#[test]
fn blank_image_yields_no_text() {
    let png = render_line_png("   ", 2);
    assert_eq!(extract(&png), OcrOutcome::Skipped(OcrSkip::NoText));
}

#[test]
fn malformed_png_is_skipped_not_panicking() {
    // Valid PNG magic, truncated body.
    let mut bytes = vec![0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a];
    bytes.extend_from_slice(b"\x00\x00\x00\x0dIHDR");
    assert_eq!(extract(&bytes), OcrOutcome::Skipped(OcrSkip::DecodeFailed));
}

#[test]
fn decodes_netpbm_p5_grayscale() {
    // 4x2 P5: a black and white checker; verify dimensions + luma orientation.
    let mut bytes = b"P5\n4 2\n255\n".to_vec();
    bytes.extend_from_slice(&[0, 255, 0, 255, 255, 0, 255, 0]);
    let img = super::decode::decode(&bytes, 4096, 4_000_000).expect("decode pgm");
    assert_eq!((img.width, img.height), (4, 2));
    assert_eq!(img.luma, vec![0, 255, 0, 255, 255, 0, 255, 0]);
}

#[test]
fn decodes_bmp_24bit_bottom_up() {
    // 2x2 24-bit BMP, rows stored bottom-up; expect top-down luma after decode.
    let bytes = bmp_24bit_2x2();
    let img = super::decode::decode(&bytes, 4096, 4_000_000).expect("decode bmp");
    assert_eq!((img.width, img.height), (2, 2));
    // Top row was written last (bottom-up): white, black; bottom row: black, white.
    assert_eq!(img.luma, vec![255, 0, 0, 255]);
}

#[test]
fn netpbm_with_overlarge_dimensions_is_oversized() {
    let bytes = b"P5\n100 100\n255\n".to_vec();
    let err = super::decode::decode(&bytes, 4096, 16).unwrap_err();
    assert_eq!(err, super::decode::DecodeError::Oversized);
}

#[test]
fn secret_in_screenshot_is_detected_by_existing_classifier() {
    // The headline guarantee: a credit-card number that exists only inside an
    // image is recovered by OCR and then flagged by the unchanged detector.
    let png = render_line_png("Card 4111 1111 1111 1111", 3);
    let text = text_of(extract(&png));
    assert!(
        text.contains("4111 1111 1111 1111"),
        "ocr text was {text:?}"
    );

    let rule = DlpRule {
        id: "cc".into(),
        name: "Credit card".into(),
        pattern_type: PatternType::Regex,
        pattern_data: "credit_card".into(),
        severity: Severity::Critical,
        action: RuleAction::Block,
        channels: Vec::new(),
    };
    let classifier = ContentClassifier::compile(&[rule]).expect("compile");
    let result = classifier.classify(
        DlpChannel::BrowserUpload,
        text.as_bytes(),
        &ContentMetadata::default(),
    );
    assert!(
        result.is_match(),
        "classifier did not flag the OCR'd card number"
    );
    assert_eq!(result.strictest_action(), Some(RuleAction::Block));
}

#[test]
fn engine_blocks_secret_embedded_in_image_via_ocr_hook() {
    // End-to-end through the real engine hook: a screenshot whose ONLY secret
    // is the rendered card number must be blocked by `DlpEngine::evaluate`,
    // proving the additive OCR pass feeds the existing classifier.
    use crate::engine::DlpEngine;
    use crate::policy::DlpPolicy;

    let cc_rule = DlpRule {
        id: "cc".into(),
        name: "Credit card".into(),
        pattern_type: PatternType::Regex,
        pattern_data: "credit_card".into(),
        severity: Severity::Critical,
        action: RuleAction::Block,
        channels: Vec::new(),
    };
    let engine = DlpEngine::new(DlpPolicy {
        rules: vec![cc_rule],
        ..DlpPolicy::default()
    })
    .expect("engine");

    let png = render_line_png("Card 4111 1111 1111 1111", 3);
    let verdict = engine.evaluate(DlpChannel::BrowserUpload, &png, &ContentMetadata::default());
    assert!(
        verdict.is_blocking(),
        "engine did not block the OCR'd card: {verdict:?}"
    );
    let details = verdict.details().expect("verdict details");
    assert_eq!(details.action, RuleAction::Block);
    assert_eq!(details.severity, Severity::Critical);

    // Existing text path is unchanged: a plain (non-image) payload with no
    // secret is still allowed, and the cheap header sniff means OCR never runs.
    let allow = engine.evaluate(
        DlpChannel::BrowserUpload,
        b"just an ordinary sentence with no secrets",
        &ContentMetadata::default(),
    );
    assert!(
        !allow.is_blocking(),
        "unexpected block on benign text: {allow:?}"
    );
}

/// Build a minimal 2x2 24-bit uncompressed BMP, rows bottom-up:
/// stored order (bottom→top): [black, white] then [white, black].
fn bmp_24bit_2x2() -> Vec<u8> {
    let width = 2i32;
    let height = 2i32;
    let row_stride = (width as usize * 3).div_ceil(4) * 4; // 8 bytes (6 + 2 pad)
    let pixel_offset = 14 + 40usize;
    let image_size = row_stride * height as usize;
    let file_size = pixel_offset + image_size;

    let mut b = Vec::with_capacity(file_size);
    // BITMAPFILEHEADER
    b.extend_from_slice(b"BM");
    b.extend_from_slice(&(file_size as u32).to_le_bytes());
    b.extend_from_slice(&0u16.to_le_bytes());
    b.extend_from_slice(&0u16.to_le_bytes());
    b.extend_from_slice(&(pixel_offset as u32).to_le_bytes());
    // BITMAPINFOHEADER (40 bytes)
    b.extend_from_slice(&40u32.to_le_bytes());
    b.extend_from_slice(&width.to_le_bytes());
    b.extend_from_slice(&height.to_le_bytes());
    b.extend_from_slice(&1u16.to_le_bytes()); // planes
    b.extend_from_slice(&24u16.to_le_bytes()); // bpp
    b.extend_from_slice(&0u32.to_le_bytes()); // BI_RGB
    b.extend_from_slice(&(image_size as u32).to_le_bytes());
    b.extend_from_slice(&2835u32.to_le_bytes()); // x ppm
    b.extend_from_slice(&2835u32.to_le_bytes()); // y ppm
    b.extend_from_slice(&0u32.to_le_bytes()); // palette colors
    b.extend_from_slice(&0u32.to_le_bytes()); // important colors

    let black = [0u8, 0, 0];
    let white = [255u8, 255, 255];
    // bottom row first: black, white
    let mut row0 = Vec::new();
    row0.extend_from_slice(&black);
    row0.extend_from_slice(&white);
    row0.resize(row_stride, 0);
    // top row: white, black
    let mut row1 = Vec::new();
    row1.extend_from_slice(&white);
    row1.extend_from_slice(&black);
    row1.resize(row_stride, 0);
    b.extend_from_slice(&row0);
    b.extend_from_slice(&row1);
    b
}
