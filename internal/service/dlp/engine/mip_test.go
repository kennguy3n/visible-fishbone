package engine

import (
	"archive/zip"
	"bytes"
	"testing"
)

func TestMIPReader_EmailHeaders(t *testing.T) {
	r := NewMIPReader()
	content := []byte("From: alice@corp.com\r\nX-MS-InformationProtection-Label: confidential-guid-123\r\n\r\nBody here.")
	labels, err := r.ReadMIPLabels(content, "message/rfc822")
	if err != nil {
		t.Fatalf("ReadMIPLabels: %v", err)
	}
	if len(labels) != 1 {
		t.Fatalf("expected 1 label, got %d", len(labels))
	}
	if labels[0].LabelID != "confidential-guid-123" {
		t.Errorf("unexpected label ID: %q", labels[0].LabelID)
	}
}

func TestMIPReader_NoHeaders(t *testing.T) {
	r := NewMIPReader()
	content := []byte("From: alice@corp.com\r\nSubject: Hello\r\n\r\nBody here.")
	labels, err := r.ReadMIPLabels(content, "text/plain")
	if err != nil {
		t.Fatalf("ReadMIPLabels: %v", err)
	}
	if len(labels) != 0 {
		t.Fatalf("expected 0 labels, got %d", len(labels))
	}
}

func TestMIPReader_OOXML(t *testing.T) {
	r := NewMIPReader()
	// Build a minimal OOXML (ZIP) with custom.xml containing MIP props.
	customXML := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/custom-properties"
            xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes">
  <property fmtid="{D5CDD505-2E9C-101B-9397-08002B2CF9AE}" pid="2" name="MSIP_Label_abcd-1234_Enabled">
    <vt:lpwstr>true</vt:lpwstr>
  </property>
  <property fmtid="{D5CDD505-2E9C-101B-9397-08002B2CF9AE}" pid="3" name="MSIP_Label_abcd-1234_Name">
    <vt:lpwstr>Highly Confidential</vt:lpwstr>
  </property>
</Properties>`

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	fw, err := zw.Create("docProps/custom.xml")
	if err != nil {
		t.Fatalf("zip create: %v", err)
	}
	if _, err := fw.Write([]byte(customXML)); err != nil {
		t.Fatalf("zip write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}

	labels, err := r.ReadMIPLabels(buf.Bytes(), "application/vnd.openxmlformats-officedocument.wordprocessingml.document")
	if err != nil {
		t.Fatalf("ReadMIPLabels: %v", err)
	}
	if len(labels) != 1 {
		t.Fatalf("expected 1 label, got %d", len(labels))
	}
	if labels[0].LabelID != "abcd-1234" {
		t.Errorf("unexpected label ID: %q", labels[0].LabelID)
	}
	if labels[0].Sensitivity != "Highly Confidential" {
		t.Errorf("unexpected sensitivity: %q", labels[0].Sensitivity)
	}
}

func TestMIPReader_BodyNotScanned(t *testing.T) {
	r := NewMIPReader()
	// MIP header only in body after the blank-line separator — must not match.
	content := []byte("From: alice@corp.com\r\nSubject: Hello\r\n\r\nX-MS-InformationProtection-Label: fake-label")
	labels, err := r.ReadMIPLabels(content, "message/rfc822")
	if err != nil {
		t.Fatalf("ReadMIPLabels: %v", err)
	}
	if len(labels) != 0 {
		t.Fatalf("expected 0 labels from body, got %d", len(labels))
	}
}

func TestMIPReader_CaseInsensitiveHeader(t *testing.T) {
	r := NewMIPReader()
	content := []byte("From: alice@corp.com\r\nX-Ms-Informationprotection-Label: mixed-case-guid\r\n\r\nBody.")
	labels, err := r.ReadMIPLabels(content, "message/rfc822")
	if err != nil {
		t.Fatalf("ReadMIPLabels: %v", err)
	}
	if len(labels) != 1 {
		t.Fatalf("expected 1 label, got %d", len(labels))
	}
	if labels[0].LabelID != "mixed-case-guid" {
		t.Errorf("unexpected label ID: %q", labels[0].LabelID)
	}
}

func TestMIPReader_InvalidZip(t *testing.T) {
	r := NewMIPReader()
	_, err := r.ReadMIPLabels([]byte("not a zip"), "application/vnd.openxmlformats-officedocument.wordprocessingml.document")
	if err == nil {
		t.Fatal("expected error for invalid zip")
	}
}
