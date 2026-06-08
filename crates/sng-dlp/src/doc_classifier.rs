//! Document-type classification by *content analysis*.
//!
//! The endpoint frequently sees a buffer with a misleading (or
//! absent) filename — a macro-enabled spreadsheet renamed `notes.txt`,
//! a password-protected archive with no extension, a screenshot pasted
//! from the clipboard. Trusting the declared extension or MIME type is
//! a DLP gap, so [`classify_document`] sniffs the bytes directly:
//!
//! * **PDF** — header sniff, plus a bounded scan for an encryption
//!   dictionary (`/Encrypt`) and interactive form fields
//!   (`/AcroForm`, `/XFA`).
//! * **Office Open XML** (`.docx`/`.xlsx`/`.pptx`) — these are ZIP
//!   containers, so the central directory is parsed (no decompression)
//!   to spot the `[Content_Types].xml` marker and then macro projects
//!   (`vbaProject.bin`), embedded OLE objects (`/embeddings/`), and
//!   external workbook links (`xl/externalLinks/`).
//! * **Archives** — ZIP, gzip, and friends; a ZIP's central directory
//!   reveals password-protected entries (the per-entry encrypted flag)
//!   and nested archives.
//! * **Images** — PNG/JPEG/GIF/BMP/TIFF magic; PNG dimensions are read
//!   from the `IHDR` chunk to flag screen-resolution screenshots, and
//!   JPEGs are flagged as OCR-ready photos of documents.
//!
//! Each classification carries a **risk score** in `0.0..=1.0` (e.g. a
//! macro-enabled workbook scores high) that the DLP verdict pipeline
//! feeds into contextual scoring. Like the rest of the engine this
//! module is metadata-only: it reports *what kind* of document a buffer
//! is and *which structural risk signals* it carries, never the
//! content itself.

use crate::classifier::ContentMetadata;
use serde::{Deserialize, Serialize};

/// How many leading bytes of a (potentially huge) buffer the
/// text-oriented scanners (PDF keyword search) inspect. PDF structural
/// markers we care about — the header, the trailer's `/Encrypt`
/// reference, and the `/AcroForm` catalog entry — live in the first
/// tens of kilobytes for the overwhelming majority of real documents,
/// and bounding the scan keeps classification O(1) in document size.
const PDF_SCAN_LIMIT: usize = 64 * 1024;

/// Upper bound on the number of ZIP central-directory entries walked.
/// A real OOXML document has well under a hundred parts; this guards a
/// crafted archive with a pathological entry count from turning
/// classification into a DoS.
const MAX_ZIP_ENTRIES: usize = 4096;

/// The kind of an Office Open XML package.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OoxmlKind {
    /// Word document (`word/` parts).
    Document,
    /// Excel workbook (`xl/` parts).
    Spreadsheet,
    /// PowerPoint presentation (`ppt/` parts).
    Presentation,
    /// A `[Content_Types].xml` OOXML package whose primary part
    /// directory was not recognised.
    Unknown,
}

/// The kind of a raster image.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImageKind {
    Png,
    Jpeg,
    Gif,
    Bmp,
    Tiff,
}

/// The kind of an archive container.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArchiveKind {
    Zip,
    Gzip,
    Bzip2,
    Xz,
    SevenZip,
    Rar,
    Tar,
}

/// The detected document type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DocumentType {
    Pdf,
    Ooxml(OoxmlKind),
    /// Legacy OLE2 compound file (`.doc`/`.xls`/`.ppt`, `.msg`).
    OleCompound,
    Image(ImageKind),
    Archive(ArchiveKind),
    /// Decodes as predominantly printable text.
    PlainText,
    /// No signature matched.
    Unknown,
}

/// A structural risk signal discovered during classification.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DocSignal {
    /// The Office package carries a VBA macro project.
    MacroEnabled,
    /// The Office package embeds OLE objects.
    EmbeddedObjects,
    /// The workbook references external (off-document) links.
    ExternalLinks,
    /// The PDF declares an encryption dictionary, or an archive entry
    /// is password-protected.
    Encrypted,
    /// The PDF carries interactive form fields (`AcroForm`/`XFA`).
    FormFields,
    /// The archive contains a further nested archive.
    NestedArchive,
    /// A PNG at a common screen resolution — likely a screenshot.
    Screenshot,
    /// A JPEG photo — likely a captured photo of a document (OCR-ready
    /// exfiltration path that bypasses text scanning).
    PhotoOfDocument,
}

/// Coarse risk band derived from [`DocumentClassification::risk`], for
/// operators who prefer thresholds to raw scores.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

/// The result of [`classify_document`]: the detected type, the
/// structural risk signals, and an aggregate risk score.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DocumentClassification {
    /// The detected document type.
    pub doc_type: DocumentType,
    /// Aggregate structural risk in `0.0..=1.0`.
    pub risk: f64,
    /// The individual signals that contributed to `risk`, in detection
    /// order and de-duplicated.
    pub signals: Vec<DocSignal>,
}

impl Default for DocumentClassification {
    /// An unknown, zero-risk document — the result for an empty or
    /// unrecognised buffer, and the neutral value the classifier uses
    /// before any content is inspected.
    fn default() -> Self {
        Self {
            doc_type: DocumentType::Unknown,
            risk: 0.0,
            signals: Vec::new(),
        }
    }
}

impl DocumentClassification {
    /// The coarse [`RiskLevel`] band for [`Self::risk`].
    #[must_use]
    pub fn risk_level(&self) -> RiskLevel {
        if self.risk >= 0.75 {
            RiskLevel::Critical
        } else if self.risk >= 0.5 {
            RiskLevel::High
        } else if self.risk >= 0.25 {
            RiskLevel::Medium
        } else {
            RiskLevel::Low
        }
    }

    /// Whether a particular signal is present.
    #[must_use]
    pub fn has_signal(&self, signal: DocSignal) -> bool {
        self.signals.contains(&signal)
    }

    fn push_signal(&mut self, signal: DocSignal, weight: f64) {
        if !self.signals.contains(&signal) {
            self.signals.push(signal);
            self.risk = (self.risk + weight).min(1.0);
        }
    }
}

/// Common screen resolutions (width, height) used to flag a PNG as a
/// likely screenshot. Orientation-independent: both `w×h` and `h×w`
/// match.
const SCREEN_RESOLUTIONS: &[(u32, u32)] = &[
    (1280, 720),
    (1280, 800),
    (1366, 768),
    (1440, 900),
    (1536, 864),
    (1600, 900),
    (1680, 1050),
    (1920, 1080),
    (1920, 1200),
    (2048, 1152),
    (2560, 1440),
    (2560, 1600),
    (2880, 1800),
    (3440, 1440),
    (3840, 2160),
];

/// Classify a content buffer by inspecting its bytes. `metadata` is
/// advisory only (filename / declared MIME used as a weak tie-breaker
/// for ambiguous text); the byte signature always wins so a renamed or
/// mis-typed file is classified by what it actually is.
#[must_use]
pub fn classify_document(content: &[u8], metadata: &ContentMetadata) -> DocumentClassification {
    if let Some(c) = classify_pdf(content) {
        return c;
    }
    if starts_with(content, b"PK\x03\x04") || starts_with(content, b"PK\x05\x06") {
        return classify_zip_family(content);
    }
    if let Some(kind) = sniff_image(content) {
        return classify_image(content, kind);
    }
    if let Some(kind) = sniff_non_zip_archive(content) {
        return base(DocumentType::Archive(kind), archive_base_risk(kind));
    }
    if starts_with(content, &[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]) {
        // OLE2 compound document (legacy Office, Outlook .msg).
        return base(DocumentType::OleCompound, 0.35);
    }
    if looks_like_text(content, metadata) {
        return base(DocumentType::PlainText, 0.0);
    }
    base(DocumentType::Unknown, 0.0)
}

fn base(doc_type: DocumentType, risk: f64) -> DocumentClassification {
    DocumentClassification {
        doc_type,
        risk: risk.clamp(0.0, 1.0),
        signals: Vec::new(),
    }
}

fn starts_with(content: &[u8], prefix: &[u8]) -> bool {
    content.len() >= prefix.len() && &content[..prefix.len()] == prefix
}

// ---- PDF -----------------------------------------------------------

fn classify_pdf(content: &[u8]) -> Option<DocumentClassification> {
    if !starts_with(content, b"%PDF-") {
        return None;
    }
    let mut c = base(DocumentType::Pdf, 0.2);
    let head = &content[..content.len().min(PDF_SCAN_LIMIT)];
    let tail_start = content.len().saturating_sub(PDF_SCAN_LIMIT);
    let tail = &content[tail_start..];
    // `/Encrypt` lives in the trailer (end of file); `/AcroForm` and
    // XFA live in the document catalog near the head. Scan both ends.
    if contains(head, b"/Encrypt") || contains(tail, b"/Encrypt") {
        c.push_signal(DocSignal::Encrypted, 0.2);
    }
    if contains(head, b"/AcroForm") || contains(head, b"/XFA") {
        c.push_signal(DocSignal::FormFields, 0.2);
    }
    Some(c)
}

// ---- ZIP family (archives + OOXML) ---------------------------------

/// A parsed ZIP central-directory entry (metadata only).
struct ZipEntry {
    name: String,
    encrypted: bool,
}

fn classify_zip_family(content: &[u8]) -> DocumentClassification {
    let entries = parse_zip_central_directory(content);
    let any_encrypted = entries.iter().any(|e| e.encrypted);

    // An OOXML package is a ZIP carrying `[Content_Types].xml`.
    if entries.iter().any(|e| e.name == "[Content_Types].xml") {
        return classify_ooxml(&entries);
    }

    // Otherwise a plain ZIP archive.
    let mut c = base(DocumentType::Archive(ArchiveKind::Zip), 0.2);
    if any_encrypted {
        c.push_signal(DocSignal::Encrypted, 0.3);
    }
    if entries.iter().any(|e| is_archive_name(&e.name)) {
        c.push_signal(DocSignal::NestedArchive, 0.2);
    }
    c
}

fn classify_ooxml(entries: &[ZipEntry]) -> DocumentClassification {
    let kind = ooxml_kind(entries);
    let mut c = base(DocumentType::Ooxml(kind), 0.2);
    if entries
        .iter()
        .any(|e| e.name.rsplit('/').next() == Some("vbaProject.bin"))
    {
        c.push_signal(DocSignal::MacroEnabled, 0.5);
    }
    if entries.iter().any(|e| e.name.contains("/embeddings/")) {
        c.push_signal(DocSignal::EmbeddedObjects, 0.2);
    }
    if entries.iter().any(|e| e.name.contains("externalLinks/")) {
        c.push_signal(DocSignal::ExternalLinks, 0.15);
    }
    // A package whose own parts are encrypted (rare for OOXML, but
    // valid) is as risky as a password-protected archive.
    if entries.iter().any(|e| e.encrypted) {
        c.push_signal(DocSignal::Encrypted, 0.2);
    }
    c
}

fn ooxml_kind(entries: &[ZipEntry]) -> OoxmlKind {
    let has = |prefix: &str| entries.iter().any(|e| e.name.starts_with(prefix));
    if has("word/") {
        OoxmlKind::Document
    } else if has("xl/") {
        OoxmlKind::Spreadsheet
    } else if has("ppt/") {
        OoxmlKind::Presentation
    } else {
        OoxmlKind::Unknown
    }
}

/// Parse a ZIP central directory into entries (names + encrypted
/// flag). Returns an empty vector on any malformed structure — a
/// buffer we cannot parse simply yields no OOXML/encryption signals
/// rather than a panic. No entry data is decompressed or copied.
fn parse_zip_central_directory(content: &[u8]) -> Vec<ZipEntry> {
    let Some(eocd) = find_eocd(content) else {
        return Vec::new();
    };
    // EOCD layout: signature(4) disk(2) cd_disk(2) disk_entries(2)
    // total_entries(2) cd_size(4) cd_offset(4) comment_len(2).
    let total_entries = read_u16(content, eocd + 10) as usize;
    let cd_offset = read_u32(content, eocd + 16) as usize;
    let mut out = Vec::new();
    let mut pos = cd_offset;
    for _ in 0..total_entries.min(MAX_ZIP_ENTRIES) {
        // Central file header signature 0x02014b50.
        if pos + 46 > content.len() || read_u32(content, pos) != 0x0201_4b50 {
            break;
        }
        let flags = read_u16(content, pos + 8);
        let name_len = read_u16(content, pos + 28) as usize;
        let extra_len = read_u16(content, pos + 30) as usize;
        let comment_len = read_u16(content, pos + 32) as usize;
        let name_start = pos + 46;
        let name_end = name_start + name_len;
        if name_end > content.len() {
            break;
        }
        let name = String::from_utf8_lossy(&content[name_start..name_end]).into_owned();
        out.push(ZipEntry {
            name,
            // General-purpose bit 0 marks a password-protected entry.
            encrypted: flags & 0x0001 != 0,
        });
        pos = name_end + extra_len + comment_len;
    }
    out
}

/// Locate the End Of Central Directory record by scanning backwards
/// for its `PK\x05\x06` signature (the trailing comment is bounded at
/// 64 KiB by the spec, so a bounded backward scan suffices).
fn find_eocd(content: &[u8]) -> Option<usize> {
    const EOCD_MIN: usize = 22;
    if content.len() < EOCD_MIN {
        return None;
    }
    let max_back = content.len().min(EOCD_MIN + 0xFFFF);
    let start = content.len() - max_back;
    let window = &content[start..];
    // Search backwards for the signature.
    for i in (0..=window.len() - 4).rev() {
        if window[i] == b'P' && window[i + 1] == b'K' && window[i + 2] == 5 && window[i + 3] == 6 {
            let abs = start + i;
            if abs + EOCD_MIN <= content.len() {
                return Some(abs);
            }
        }
    }
    None
}

fn read_u16(b: &[u8], at: usize) -> u16 {
    if at + 2 > b.len() {
        return 0;
    }
    u16::from_le_bytes([b[at], b[at + 1]])
}

fn read_u32(b: &[u8], at: usize) -> u32 {
    if at + 4 > b.len() {
        return 0;
    }
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

fn is_archive_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    [
        ".zip", ".rar", ".7z", ".gz", ".tgz", ".tar", ".bz2", ".xz", ".cab",
    ]
    .iter()
    .any(|ext| lower.ends_with(ext))
}

fn archive_base_risk(kind: ArchiveKind) -> f64 {
    match kind {
        // Single-stream compressors carry no directory we can inspect
        // for nested/encrypted content, so they start a touch lower.
        ArchiveKind::Gzip | ArchiveKind::Bzip2 | ArchiveKind::Xz => 0.15,
        _ => 0.2,
    }
}

fn sniff_non_zip_archive(content: &[u8]) -> Option<ArchiveKind> {
    if starts_with(content, &[0x1F, 0x8B]) {
        Some(ArchiveKind::Gzip)
    } else if starts_with(content, b"BZh") {
        Some(ArchiveKind::Bzip2)
    } else if starts_with(content, &[0xFD, b'7', b'z', b'X', b'Z', 0x00]) {
        Some(ArchiveKind::Xz)
    } else if starts_with(content, &[b'7', b'z', 0xBC, 0xAF, 0x27, 0x1C]) {
        Some(ArchiveKind::SevenZip)
    } else if starts_with(content, b"Rar!\x1a\x07") {
        Some(ArchiveKind::Rar)
    } else if content.len() > 262 && &content[257..262] == b"ustar" {
        Some(ArchiveKind::Tar)
    } else {
        None
    }
}

// ---- Images --------------------------------------------------------

fn sniff_image(content: &[u8]) -> Option<ImageKind> {
    if starts_with(content, &[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]) {
        Some(ImageKind::Png)
    } else if starts_with(content, &[0xFF, 0xD8, 0xFF]) {
        Some(ImageKind::Jpeg)
    } else if starts_with(content, b"GIF87a") || starts_with(content, b"GIF89a") {
        Some(ImageKind::Gif)
    } else if starts_with(content, b"BM") {
        Some(ImageKind::Bmp)
    } else if starts_with(content, &[0x49, 0x49, 0x2A, 0x00])
        || starts_with(content, &[0x4D, 0x4D, 0x00, 0x2A])
    {
        Some(ImageKind::Tiff)
    } else {
        None
    }
}

fn classify_image(content: &[u8], kind: ImageKind) -> DocumentClassification {
    let mut c = base(DocumentType::Image(kind), 0.1);
    match kind {
        ImageKind::Png => {
            if let Some((w, h)) = png_dimensions(content) {
                if is_screen_resolution(w, h) {
                    c.push_signal(DocSignal::Screenshot, 0.2);
                }
            }
        }
        ImageKind::Jpeg => {
            // A JPEG moving over a DLP channel is most often a photo or
            // a screenshot saved as JPEG — an OCR-ready exfil path that
            // bypasses text scanners entirely.
            c.push_signal(DocSignal::PhotoOfDocument, 0.15);
        }
        _ => {}
    }
    c
}

/// Read width/height from a PNG `IHDR` chunk, which the spec fixes as
/// the first chunk immediately after the 8-byte signature.
fn png_dimensions(content: &[u8]) -> Option<(u32, u32)> {
    // 8 sig + 4 len + 4 "IHDR" then width(4) height(4).
    if content.len() < 24 || &content[12..16] != b"IHDR" {
        return None;
    }
    let w = u32::from_be_bytes([content[16], content[17], content[18], content[19]]);
    let h = u32::from_be_bytes([content[20], content[21], content[22], content[23]]);
    Some((w, h))
}

fn is_screen_resolution(w: u32, h: u32) -> bool {
    SCREEN_RESOLUTIONS
        .iter()
        .any(|&(rw, rh)| (w == rw && h == rh) || (w == rh && h == rw))
}

// ---- Text fallback -------------------------------------------------

/// Heuristic: a buffer is "plain text" if a bounded prefix decodes as
/// valid UTF-8 with no NUL bytes and is overwhelmingly printable. The
/// declared MIME / extension only nudges an empty buffer.
fn looks_like_text(content: &[u8], metadata: &ContentMetadata) -> bool {
    if content.is_empty() {
        return metadata
            .content_type
            .as_deref()
            .is_some_and(|t| t.starts_with("text/"));
    }
    let head = &content[..content.len().min(PDF_SCAN_LIMIT)];
    if head.contains(&0u8) {
        return false;
    }
    let Ok(s) = std::str::from_utf8(head) else {
        return false;
    };
    let total = s.chars().count();
    if total == 0 {
        return false;
    }
    let printable = s
        .chars()
        .filter(|c| !c.is_control() || matches!(c, '\n' | '\r' | '\t'))
        .count();
    // Both counts are bounded by `PDF_SCAN_LIMIT` (64 KiB of chars),
    // far below f64's 52-bit mantissa, so the ratio is exact.
    #[allow(clippy::cast_precision_loss)]
    let ratio = printable as f64 / total as f64;
    ratio > 0.95
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// Test-only helpers shared with other modules' unit tests (e.g. the
/// `ContextualScorer` tests in `classifier`). Compiled only under
/// `cfg(test)` and never part of the shipped crate.
#[cfg(test)]
pub(crate) mod tests_support {
    /// Build a minimal ZIP whose central directory is well-formed
    /// enough for [`super::parse_zip_central_directory`]: local file
    /// headers with empty stored data, a central directory, and an
    /// EOCD. `entries` is `(name, encrypted)`.
    pub(crate) fn build_zip(entries: &[(&str, bool)]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut central = Vec::new();
        let mut offsets = Vec::new();
        for (name, encrypted) in entries {
            offsets.push(out.len() as u32);
            let flags: u16 = u16::from(*encrypted);
            out.extend_from_slice(&0x0403_4b50u32.to_le_bytes()); // local sig
            out.extend_from_slice(&20u16.to_le_bytes()); // version
            out.extend_from_slice(&flags.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes()); // method
            out.extend_from_slice(&0u32.to_le_bytes()); // time/date
            out.extend_from_slice(&0u32.to_le_bytes()); // crc
            out.extend_from_slice(&0u32.to_le_bytes()); // comp size
            out.extend_from_slice(&0u32.to_le_bytes()); // uncomp size
            out.extend_from_slice(&(name.len() as u16).to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes()); // extra len
            out.extend_from_slice(name.as_bytes());
        }
        for ((name, encrypted), off) in entries.iter().zip(offsets.iter()) {
            let flags: u16 = u16::from(*encrypted);
            central.extend_from_slice(&0x0201_4b50u32.to_le_bytes()); // central sig
            central.extend_from_slice(&20u16.to_le_bytes()); // version made by
            central.extend_from_slice(&20u16.to_le_bytes()); // version needed
            central.extend_from_slice(&flags.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes()); // method
            central.extend_from_slice(&0u32.to_le_bytes()); // time/date
            central.extend_from_slice(&0u32.to_le_bytes()); // crc
            central.extend_from_slice(&0u32.to_le_bytes()); // comp size
            central.extend_from_slice(&0u32.to_le_bytes()); // uncomp size
            central.extend_from_slice(&(name.len() as u16).to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes()); // extra len
            central.extend_from_slice(&0u16.to_le_bytes()); // comment len
            central.extend_from_slice(&0u16.to_le_bytes()); // disk start
            central.extend_from_slice(&0u16.to_le_bytes()); // int attrs
            central.extend_from_slice(&0u32.to_le_bytes()); // ext attrs
            central.extend_from_slice(&off.to_le_bytes()); // local offset
            central.extend_from_slice(name.as_bytes());
        }
        let cd_offset = out.len() as u32;
        let cd_size = central.len() as u32;
        out.extend_from_slice(&central);
        out.extend_from_slice(&0x0605_4b50u32.to_le_bytes()); // EOCD sig
        out.extend_from_slice(&0u16.to_le_bytes()); // disk
        out.extend_from_slice(&0u16.to_le_bytes()); // cd disk
        out.extend_from_slice(&(entries.len() as u16).to_le_bytes()); // disk entries
        out.extend_from_slice(&(entries.len() as u16).to_le_bytes()); // total entries
        out.extend_from_slice(&cd_size.to_le_bytes());
        out.extend_from_slice(&cd_offset.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // comment len
        out
    }
}

#[cfg(test)]
mod tests {
    use super::tests_support::build_zip;
    use super::*;

    #[test]
    fn pdf_header_is_detected() {
        let c = classify_document(b"%PDF-1.7\nrest of file", &ContentMetadata::default());
        assert_eq!(c.doc_type, DocumentType::Pdf);
        assert!(c.signals.is_empty());
    }

    #[test]
    fn encrypted_pdf_with_form_scores_higher() {
        let bytes = b"%PDF-1.7\n/AcroForm 1 0 R\ntrailer<</Encrypt 2 0 R>>";
        let c = classify_document(bytes, &ContentMetadata::default());
        assert_eq!(c.doc_type, DocumentType::Pdf);
        assert!(c.has_signal(DocSignal::Encrypted));
        assert!(c.has_signal(DocSignal::FormFields));
        assert!(c.risk > 0.5);
    }

    #[test]
    fn png_screenshot_resolution_flagged() {
        let png = make_png(1920, 1080);
        let c = classify_document(&png, &ContentMetadata::default());
        assert_eq!(c.doc_type, DocumentType::Image(ImageKind::Png));
        assert!(c.has_signal(DocSignal::Screenshot));
    }

    #[test]
    fn png_non_screen_resolution_not_flagged() {
        let png = make_png(123, 456);
        let c = classify_document(&png, &ContentMetadata::default());
        assert_eq!(c.doc_type, DocumentType::Image(ImageKind::Png));
        assert!(!c.has_signal(DocSignal::Screenshot));
    }

    #[test]
    fn jpeg_flagged_as_photo() {
        let jpeg = [0xFF, 0xD8, 0xFF, 0xE0, 0, 0];
        let c = classify_document(&jpeg, &ContentMetadata::default());
        assert_eq!(c.doc_type, DocumentType::Image(ImageKind::Jpeg));
        assert!(c.has_signal(DocSignal::PhotoOfDocument));
    }

    #[test]
    fn plain_text_detected() {
        let c = classify_document(b"just some notes here\n", &ContentMetadata::default());
        assert_eq!(c.doc_type, DocumentType::PlainText);
        assert_eq!(c.risk, 0.0);
    }

    #[test]
    fn gzip_archive_detected() {
        let c = classify_document(&[0x1F, 0x8B, 0x08, 0, 0], &ContentMetadata::default());
        assert_eq!(c.doc_type, DocumentType::Archive(ArchiveKind::Gzip));
    }

    #[test]
    fn macro_enabled_xlsx_is_high_risk() {
        let zip = build_zip(&[
            ("[Content_Types].xml", false),
            ("xl/workbook.xml", false),
            ("xl/vbaProject.bin", false),
        ]);
        let c = classify_document(&zip, &ContentMetadata::default());
        assert_eq!(c.doc_type, DocumentType::Ooxml(OoxmlKind::Spreadsheet));
        assert!(c.has_signal(DocSignal::MacroEnabled));
        assert!(matches!(
            c.risk_level(),
            RiskLevel::High | RiskLevel::Critical
        ));
    }

    #[test]
    fn ooxml_external_links_and_embeddings_flagged() {
        let zip = build_zip(&[
            ("[Content_Types].xml", false),
            ("xl/workbook.xml", false),
            ("xl/externalLinks/externalLink1.xml", false),
            ("xl/embeddings/oleObject1.bin", false),
        ]);
        let c = classify_document(&zip, &ContentMetadata::default());
        assert_eq!(c.doc_type, DocumentType::Ooxml(OoxmlKind::Spreadsheet));
        assert!(c.has_signal(DocSignal::ExternalLinks));
        assert!(c.has_signal(DocSignal::EmbeddedObjects));
    }

    #[test]
    fn password_protected_zip_flagged() {
        let zip = build_zip(&[("secret.txt", true)]);
        let c = classify_document(&zip, &ContentMetadata::default());
        assert_eq!(c.doc_type, DocumentType::Archive(ArchiveKind::Zip));
        assert!(c.has_signal(DocSignal::Encrypted));
    }

    #[test]
    fn nested_archive_flagged() {
        let zip = build_zip(&[("inner.zip", false), ("notes.txt", false)]);
        let c = classify_document(&zip, &ContentMetadata::default());
        assert_eq!(c.doc_type, DocumentType::Archive(ArchiveKind::Zip));
        assert!(c.has_signal(DocSignal::NestedArchive));
    }

    #[test]
    fn renamed_macro_doc_is_classified_by_content_not_extension() {
        // Declared as a .txt, but the bytes are a macro-enabled OOXML.
        let zip = build_zip(&[
            ("[Content_Types].xml", false),
            ("word/document.xml", false),
            ("word/vbaProject.bin", false),
        ]);
        let meta = ContentMetadata {
            filename: Some("harmless.txt".to_owned()),
            content_type: Some("text/plain".to_owned()),
            ..ContentMetadata::default()
        };
        let c = classify_document(&zip, &meta);
        assert_eq!(c.doc_type, DocumentType::Ooxml(OoxmlKind::Document));
        assert!(c.has_signal(DocSignal::MacroEnabled));
    }

    #[test]
    fn risk_is_clamped_and_banded() {
        let c = DocumentClassification {
            doc_type: DocumentType::Pdf,
            risk: 1.0,
            signals: vec![],
        };
        assert_eq!(c.risk_level(), RiskLevel::Critical);
        let low = base(DocumentType::PlainText, 0.0);
        assert_eq!(low.risk_level(), RiskLevel::Low);
    }

    fn make_png(w: u32, h: u32) -> Vec<u8> {
        let mut v = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
        v.extend_from_slice(&[0, 0, 0, 13]); // IHDR length
        v.extend_from_slice(b"IHDR");
        v.extend_from_slice(&w.to_be_bytes());
        v.extend_from_slice(&h.to_be_bytes());
        v.extend_from_slice(&[8, 6, 0, 0, 0]); // bit depth, colour, etc.
        v
    }
}
