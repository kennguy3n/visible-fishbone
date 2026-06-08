package providers

import "testing"

func TestDetectFileType(t *testing.T) {
	zipDoc := append([]byte("PK\x03\x04"), []byte("....[Content_Types].xml....")...)
	plainZip := append([]byte("PK\x03\x04"), []byte("just some archived files")...)

	cases := []struct {
		name    string
		content []byte
		want    FileType
	}{
		{"empty", nil, FileTypeUnknown},
		{"tiny", []byte{0x4d}, FileTypeUnknown},
		{"pe", []byte("MZ\x90\x00\x03"), FileTypePE},
		{"elf", []byte{0x7f, 'E', 'L', 'F', 0x02}, FileTypeELF},
		{"macho64", []byte{0xCF, 0xFA, 0xED, 0xFE, 0x07}, FileTypeMachO}, // little-endian 0xFEEDFACF
		{"macho_fat", []byte{0xCA, 0xFE, 0xBA, 0xBE, 0x00}, FileTypeMachO},
		{"pdf", []byte("%PDF-1.7"), FileTypePDF},
		{"ole", []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1, 0x00}, FileTypeOLE},
		{"script", []byte("#!/bin/sh\necho hi"), FileTypeScript},
		{"ooxml", zipDoc, FileTypeOOXML},
		{"zip", plainZip, FileTypeZIP},
		{"text", []byte("just plain text content"), FileTypeUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := DetectFileType(tc.content); got != tc.want {
				t.Fatalf("DetectFileType(%s) = %s, want %s", tc.name, got, tc.want)
			}
		})
	}
}

func TestFileType_Predicates(t *testing.T) {
	if !FileTypePE.Executable() || !FileTypeELF.Executable() || !FileTypeMachO.Executable() {
		t.Fatalf("binary types must be Executable")
	}
	if FileTypePDF.Executable() || FileTypeOLE.Executable() {
		t.Fatalf("documents must not be Executable")
	}
	if !FileTypeOLE.Document() || !FileTypeOOXML.Document() || !FileTypePDF.Document() {
		t.Fatalf("document types must be Document")
	}
	if FileTypePE.Document() || FileTypeUnknown.Document() {
		t.Fatalf("non-documents must not be Document")
	}
}
