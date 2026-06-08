package providers

import (
	"bytes"
	"encoding/binary"
)

// FileType is a coarse file-format classification derived from magic
// bytes. WS3 requires the sandbox path to determine a file's type
// before submission so the orchestrator can (a) skip submitting
// types a detonation backend cannot execute, (b) record the type on
// the verdict for triage, and (c) reject obviously-benign inert
// types early. The detection is header-only — it never parses the
// full file — so it is cheap and safe to run on the hot path.
type FileType string

const (
	// FileTypeUnknown is the zero value: no recognised signature.
	FileTypeUnknown FileType = "unknown"
	// FileTypePE is a Windows PE executable / DLL ("MZ").
	FileTypePE FileType = "pe"
	// FileTypeELF is a Unix ELF executable / shared object.
	FileTypeELF FileType = "elf"
	// FileTypeMachO is a macOS Mach-O executable (incl. fat/universal).
	FileTypeMachO FileType = "macho"
	// FileTypePDF is a PDF document ("%PDF").
	FileTypePDF FileType = "pdf"
	// FileTypeOLE is a legacy OLE2 compound-file Office document
	// (.doc/.xls/.ppt) — the classic macro-malware carrier.
	FileTypeOLE FileType = "ole"
	// FileTypeOOXML is a ZIP-container Office document
	// (.docx/.xlsx/.pptx) or any other ZIP-based format.
	FileTypeOOXML FileType = "ooxml"
	// FileTypeZIP is a ZIP archive that is not recognised as OOXML.
	FileTypeZIP FileType = "zip"
	// FileTypeScript is a text file beginning with a shebang
	// ("#!"), i.e. a shell/interpreter script.
	FileTypeScript FileType = "script"
)

// Executable reports whether the type is a natively-executable
// binary (PE/ELF/Mach-O). The orchestrator prioritises these for
// detonation.
func (f FileType) Executable() bool {
	switch f {
	case FileTypePE, FileTypeELF, FileTypeMachO:
		return true
	default:
		return false
	}
}

// Document reports whether the type is a document container that can
// carry active content (macros, embedded JS): OLE, OOXML, PDF.
func (f FileType) Document() bool {
	switch f {
	case FileTypeOLE, FileTypeOOXML, FileTypePDF:
		return true
	default:
		return false
	}
}

// Mach-O magic numbers (little- and big-endian, 32- and 64-bit) plus
// the fat/universal-binary magics.
var machoMagics = map[uint32]struct{}{
	0xFEEDFACE: {}, // 32-bit
	0xFEEDFACF: {}, // 64-bit
	0xCAFEBABE: {}, // fat/universal (big-endian)
	0xCAFEBABF: {}, // fat/universal 64 (big-endian)
}

// oleMagic is the OLE2 compound-file header (D0 CF 11 E0 A1 B1 1A E1).
var oleMagic = []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}

// DetectFileType classifies content by its leading bytes. It returns
// FileTypeUnknown for empty input or an unrecognised signature.
//
// The check order matters: container formats whose signatures are
// prefixes of, or could collide with, others are disambiguated
// before the generic fallbacks. ZIP-based formats are probed for the
// OOXML content-type marker to separate Office documents from plain
// archives.
func DetectFileType(content []byte) FileType {
	if len(content) < 4 {
		return FileTypeUnknown
	}

	// PE: "MZ" at offset 0.
	if content[0] == 'M' && content[1] == 'Z' {
		return FileTypePE
	}
	// ELF: 0x7F 'E' 'L' 'F'.
	if content[0] == 0x7F && content[1] == 'E' && content[2] == 'L' && content[3] == 'F' {
		return FileTypeELF
	}
	// Mach-O: 4-byte magic (either endianness).
	be := binary.BigEndian.Uint32(content[:4])
	le := binary.LittleEndian.Uint32(content[:4])
	if _, ok := machoMagics[be]; ok {
		return FileTypeMachO
	}
	if _, ok := machoMagics[le]; ok {
		return FileTypeMachO
	}
	// PDF: "%PDF".
	if bytes.HasPrefix(content, []byte("%PDF")) {
		return FileTypePDF
	}
	// OLE2 compound file (legacy Office).
	if bytes.HasPrefix(content, oleMagic) {
		return FileTypeOLE
	}
	// Shebang script.
	if content[0] == '#' && content[1] == '!' {
		return FileTypeScript
	}
	// ZIP container ("PK\x03\x04", or the empty-archive / spanned
	// markers PK\x05\x06 / PK\x07\x08). Disambiguate OOXML from a
	// plain archive by scanning for the OOXML content-types part.
	if content[0] == 'P' && content[1] == 'K' &&
		(content[2] == 0x03 || content[2] == 0x05 || content[2] == 0x07) {
		if looksLikeOOXML(content) {
			return FileTypeOOXML
		}
		return FileTypeZIP
	}

	return FileTypeUnknown
}

// looksLikeOOXML reports whether a ZIP container is an OOXML Office
// document. OOXML always stores "[Content_Types].xml" as (usually
// the first) archive entry; that literal therefore appears in the
// local-file-header region near the top of the file. We scan a
// bounded prefix rather than fully parsing the ZIP central directory
// — header-only detection, no decompression.
func looksLikeOOXML(content []byte) bool {
	limit := len(content)
	if limit > 4096 {
		limit = 4096
	}
	return bytes.Contains(content[:limit], []byte("[Content_Types].xml"))
}
