// Integration-test crate: relax the unwrap/expect/panic + float and
// cast lints that are idiomatic in fixture assertions, mirroring the
// `#![cfg_attr(test, ...)]` block in `crates/sng-dlp/src/lib.rs`.
// Attributes do not cross crate boundaries, so it is repeated here.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::cast_lossless,
    clippy::float_cmp
)]

//! Integration tests for the content-based document-type classifier
//! (`sng_dlp::doc_classifier`), Workstream 4 Step 2.
//!
//! These exercise the public [`classify_document`] API end-to-end over
//! synthesised but structurally real fixtures — PDFs, OOXML packages,
//! raster images, and archives — asserting both the detected type and
//! the structural risk signals/banding an operator policy keys off. The
//! fixtures are built byte-for-byte here (this is a separate crate and
//! cannot reach the in-module `tests_support` helpers) so the test is a
//! genuine parse of the wire format, not a mock.

use sng_dlp::{
    ArchiveKind, ContentMetadata, DocSignal, DocumentType, ImageKind, OoxmlKind, RiskLevel,
    classify_document,
};

// ---------------------------------------------------------------------------
// Fixture builders (self-contained — no decompression, real headers).
// ---------------------------------------------------------------------------

/// Build a minimal but well-formed ZIP central directory: a local file
/// header (empty stored payload) per entry, the central directory, and
/// an EOCD. `entries` is `(name, encrypted)`; the encrypted flag sets
/// the general-purpose bit-flag bit 0, exactly as a password-protected
/// member would.
fn build_zip(entries: &[(&str, bool)]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut central = Vec::new();
    let mut offsets = Vec::new();
    for (name, encrypted) in entries {
        offsets.push(u32::try_from(out.len()).unwrap());
        let flags = u16::from(*encrypted);
        out.extend_from_slice(&0x0403_4b50u32.to_le_bytes()); // local header sig
        out.extend_from_slice(&20u16.to_le_bytes()); // version needed
        out.extend_from_slice(&flags.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // method (stored)
        out.extend_from_slice(&0u32.to_le_bytes()); // mod time/date
        out.extend_from_slice(&0u32.to_le_bytes()); // crc32
        out.extend_from_slice(&0u32.to_le_bytes()); // comp size
        out.extend_from_slice(&0u32.to_le_bytes()); // uncomp size
        out.extend_from_slice(&u16::try_from(name.len()).unwrap().to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // extra len
        out.extend_from_slice(name.as_bytes());
    }
    for ((name, encrypted), off) in entries.iter().zip(offsets.iter()) {
        let flags = u16::from(*encrypted);
        central.extend_from_slice(&0x0201_4b50u32.to_le_bytes()); // central sig
        central.extend_from_slice(&20u16.to_le_bytes()); // version made by
        central.extend_from_slice(&20u16.to_le_bytes()); // version needed
        central.extend_from_slice(&flags.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes()); // method
        central.extend_from_slice(&0u32.to_le_bytes()); // time/date
        central.extend_from_slice(&0u32.to_le_bytes()); // crc
        central.extend_from_slice(&0u32.to_le_bytes()); // comp size
        central.extend_from_slice(&0u32.to_le_bytes()); // uncomp size
        central.extend_from_slice(&u16::try_from(name.len()).unwrap().to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes()); // extra len
        central.extend_from_slice(&0u16.to_le_bytes()); // comment len
        central.extend_from_slice(&0u16.to_le_bytes()); // disk start
        central.extend_from_slice(&0u16.to_le_bytes()); // int attrs
        central.extend_from_slice(&0u32.to_le_bytes()); // ext attrs
        central.extend_from_slice(&off.to_le_bytes()); // local offset
        central.extend_from_slice(name.as_bytes());
    }
    let cd_offset = u32::try_from(out.len()).unwrap();
    let cd_size = u32::try_from(central.len()).unwrap();
    out.extend_from_slice(&central);
    out.extend_from_slice(&0x0605_4b50u32.to_le_bytes()); // EOCD sig
    out.extend_from_slice(&0u16.to_le_bytes()); // disk
    out.extend_from_slice(&0u16.to_le_bytes()); // cd disk
    out.extend_from_slice(&u16::try_from(entries.len()).unwrap().to_le_bytes());
    out.extend_from_slice(&u16::try_from(entries.len()).unwrap().to_le_bytes());
    out.extend_from_slice(&cd_size.to_le_bytes());
    out.extend_from_slice(&cd_offset.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // comment len
    out
}

/// A minimal PNG: signature + an `IHDR` chunk carrying `w`×`h`. Enough
/// for the classifier's dimension probe and screenshot heuristic.
fn make_png(w: u32, h: u32) -> Vec<u8> {
    let mut v = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
    v.extend_from_slice(&[0, 0, 0, 13]); // IHDR length
    v.extend_from_slice(b"IHDR");
    v.extend_from_slice(&w.to_be_bytes());
    v.extend_from_slice(&h.to_be_bytes());
    v.extend_from_slice(&[8, 6, 0, 0, 0]); // depth, colour type, ...
    v
}

// ---------------------------------------------------------------------------
// PDF
// ---------------------------------------------------------------------------

#[test]
fn pdf_is_detected_from_header() {
    let c = classify_document(
        b"%PDF-1.7\n1 0 obj\n<<>>\nendobj\n",
        &ContentMetadata::default(),
    );
    assert_eq!(c.doc_type, DocumentType::Pdf);
    assert!(c.signals.is_empty());
    assert_eq!(c.risk_level(), RiskLevel::Low);
}

#[test]
fn encrypted_pdf_with_form_fields_is_high_risk() {
    let bytes = b"%PDF-1.7\n/AcroForm 3 0 R\ntrailer<</Encrypt 5 0 R>>";
    let c = classify_document(bytes, &ContentMetadata::default());
    assert_eq!(c.doc_type, DocumentType::Pdf);
    assert!(c.has_signal(DocSignal::Encrypted));
    assert!(c.has_signal(DocSignal::FormFields));
    assert!(c.risk > 0.5, "risk={}", c.risk);
}

// ---------------------------------------------------------------------------
// Office Open XML
// ---------------------------------------------------------------------------

#[test]
fn macro_enabled_workbook_is_classified_and_high_risk() {
    let xlsm = build_zip(&[
        ("[Content_Types].xml", false),
        ("xl/workbook.xml", false),
        ("xl/vbaProject.bin", false),
    ]);
    let c = classify_document(&xlsm, &ContentMetadata::default());
    assert_eq!(c.doc_type, DocumentType::Ooxml(OoxmlKind::Spreadsheet));
    assert!(c.has_signal(DocSignal::MacroEnabled));
    assert!(
        c.risk >= 0.5,
        "macro doc should be at least High, risk={}",
        c.risk
    );
}

#[test]
fn workbook_external_links_and_embeddings_are_flagged() {
    let xlsx = build_zip(&[
        ("[Content_Types].xml", false),
        ("xl/workbook.xml", false),
        ("xl/externalLinks/externalLink1.xml", false),
        ("xl/embeddings/oleObject1.bin", false),
    ]);
    let c = classify_document(&xlsx, &ContentMetadata::default());
    assert_eq!(c.doc_type, DocumentType::Ooxml(OoxmlKind::Spreadsheet));
    assert!(c.has_signal(DocSignal::ExternalLinks));
    assert!(c.has_signal(DocSignal::EmbeddedObjects));
}

#[test]
fn macro_doc_is_classified_by_content_not_extension() {
    // A `.docx`-named package that actually carries a VBA project: the
    // classifier must see the macro from the parts, not the extension.
    let docm = build_zip(&[
        ("[Content_Types].xml", false),
        ("word/document.xml", false),
        ("word/vbaProject.bin", false),
    ]);
    let c = classify_document(&docm, &ContentMetadata::default());
    assert_eq!(c.doc_type, DocumentType::Ooxml(OoxmlKind::Document));
    assert!(c.has_signal(DocSignal::MacroEnabled));
}

// ---------------------------------------------------------------------------
// Archives
// ---------------------------------------------------------------------------

#[test]
fn password_protected_zip_is_flagged_encrypted() {
    let zip = build_zip(&[("secrets.csv", true)]);
    let c = classify_document(&zip, &ContentMetadata::default());
    assert_eq!(c.doc_type, DocumentType::Archive(ArchiveKind::Zip));
    assert!(c.has_signal(DocSignal::Encrypted));
}

#[test]
fn nested_archive_is_flagged() {
    let zip = build_zip(&[("inner.zip", false), ("notes.txt", false)]);
    let c = classify_document(&zip, &ContentMetadata::default());
    assert_eq!(c.doc_type, DocumentType::Archive(ArchiveKind::Zip));
    assert!(c.has_signal(DocSignal::NestedArchive));
}

#[test]
fn gzip_archive_is_detected() {
    let c = classify_document(
        &[0x1F, 0x8B, 0x08, 0x00, 0, 0, 0, 0],
        &ContentMetadata::default(),
    );
    assert_eq!(c.doc_type, DocumentType::Archive(ArchiveKind::Gzip));
}

// ---------------------------------------------------------------------------
// Images
// ---------------------------------------------------------------------------

#[test]
fn png_at_screen_resolution_is_a_screenshot() {
    let c = classify_document(&make_png(1920, 1080), &ContentMetadata::default());
    assert_eq!(c.doc_type, DocumentType::Image(ImageKind::Png));
    assert!(c.has_signal(DocSignal::Screenshot));
}

#[test]
fn png_at_odd_resolution_is_not_a_screenshot() {
    let c = classify_document(&make_png(640, 477), &ContentMetadata::default());
    assert_eq!(c.doc_type, DocumentType::Image(ImageKind::Png));
    assert!(!c.has_signal(DocSignal::Screenshot));
}

#[test]
fn jpeg_is_flagged_as_a_photo_of_a_document() {
    let c = classify_document(&[0xFF, 0xD8, 0xFF, 0xE0, 0, 0], &ContentMetadata::default());
    assert_eq!(c.doc_type, DocumentType::Image(ImageKind::Jpeg));
    assert!(c.has_signal(DocSignal::PhotoOfDocument));
}

// ---------------------------------------------------------------------------
// Other / banding
// ---------------------------------------------------------------------------

#[test]
fn plain_text_is_detected_and_low_risk() {
    let c = classify_document(
        b"just a plain note with no markers\n",
        &ContentMetadata::default(),
    );
    assert_eq!(c.doc_type, DocumentType::PlainText);
    assert_eq!(c.risk_level(), RiskLevel::Low);
}

#[test]
fn empty_buffer_is_unknown_and_zero_risk() {
    let c = classify_document(&[], &ContentMetadata::default());
    assert_eq!(c.doc_type, DocumentType::Unknown);
    assert_eq!(c.risk, 0.0);
    assert_eq!(c.risk_level(), RiskLevel::Low);
}

#[test]
fn risk_bands_track_the_score() {
    // A macro-enabled workbook with external links + embeddings should
    // accumulate enough weight to land in the High/Critical bands.
    let loaded = build_zip(&[
        ("[Content_Types].xml", false),
        ("xl/workbook.xml", false),
        ("xl/vbaProject.bin", false),
        ("xl/externalLinks/externalLink1.xml", false),
        ("xl/embeddings/oleObject1.bin", false),
    ]);
    let c = classify_document(&loaded, &ContentMetadata::default());
    assert!(
        matches!(c.risk_level(), RiskLevel::High | RiskLevel::Critical),
        "expected High/Critical, got {:?} (risk={})",
        c.risk_level(),
        c.risk,
    );
}
