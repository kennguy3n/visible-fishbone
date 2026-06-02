package engine

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"strings"
)

// maxDecompressSize caps the bytes read from a single ZIP entry
// to guard against zip-bomb attacks (10 MB).
const maxDecompressSize = 10 << 20

// MIPLabel represents a Microsoft Information Protection label
// extracted from document metadata or email headers.
type MIPLabel struct {
	LabelID     string
	Sensitivity string
	Enabled     bool
}

// MIPReader reads MIP labels from Office documents (OOXML) and
// email headers.
type MIPReader struct{}

// NewMIPReader constructs a MIPReader.
func NewMIPReader() *MIPReader { return &MIPReader{} }

// ReadMIPLabels parses MIP labels from content. For OOXML documents
// it inspects the docProps/custom.xml within the ZIP archive. For
// email content (message/rfc822, text/plain) it scans for
// X-MS-InformationProtection headers.
func (r *MIPReader) ReadMIPLabels(content []byte, contentType string) ([]MIPLabel, error) {
	switch {
	case isOOXML(contentType):
		return r.readFromOOXML(content)
	case isEmail(contentType):
		return r.readFromHeaders(content)
	default:
		return r.readFromHeaders(content)
	}
}

func isOOXML(ct string) bool {
	ooxmlTypes := []string{
		"application/vnd.openxmlformats-officedocument",
		"application/vnd.ms-excel",
		"application/vnd.ms-powerpoint",
		"application/msword",
		"application/vnd.openxmlformats",
	}
	for _, prefix := range ooxmlTypes {
		if strings.HasPrefix(ct, prefix) {
			return true
		}
	}
	return false
}

func isEmail(ct string) bool {
	return strings.HasPrefix(ct, "message/rfc822") ||
		strings.HasPrefix(ct, "text/plain")
}

// ooxmlProperty mirrors the <property> element in custom.xml.
type ooxmlProperty struct {
	XMLName xml.Name `xml:"property"`
	Name    string   `xml:"name,attr"`
	FMTID   string   `xml:"fmtid,attr"`
	Value   string   `xml:",chardata"`
	Lpwstr  string   `xml:"lpwstr"`
	Vt      string   `xml:"vt,attr"`
}

// ooxmlProperties mirrors <Properties> root in custom.xml.
type ooxmlProperties struct {
	XMLName    xml.Name        `xml:"Properties"`
	Properties []ooxmlProperty `xml:"property"`
}

// readFromOOXML opens the ZIP archive and parses custom.xml for
// MIP label properties.
func (r *MIPReader) readFromOOXML(content []byte) ([]MIPLabel, error) {
	reader, err := zip.NewReader(bytes.NewReader(content), int64(len(content)))
	if err != nil {
		return nil, fmt.Errorf("mip: open zip: %w", err)
	}
	var customXML []byte
	for _, f := range reader.File {
		if strings.EqualFold(f.Name, "docProps/custom.xml") {
			rc, err := f.Open()
			if err != nil {
				return nil, fmt.Errorf("mip: open custom.xml: %w", err)
			}
			buf := new(bytes.Buffer)
			if _, err := buf.ReadFrom(io.LimitReader(rc, maxDecompressSize)); err != nil {
				_ = rc.Close()
				return nil, fmt.Errorf("mip: read custom.xml: %w", err)
			}
			_ = rc.Close()
			customXML = buf.Bytes()
			break
		}
	}
	if customXML == nil {
		return nil, nil
	}
	return parseMIPProperties(customXML)
}

// parseMIPProperties extracts MIP labels from the custom.xml property list.
// MIP stores labels as properties named "MSIP_Label_<GUID>_*".
func parseMIPProperties(data []byte) ([]MIPLabel, error) {
	var props ooxmlProperties
	if err := xml.Unmarshal(data, &props); err != nil {
		return nil, fmt.Errorf("mip: parse custom.xml: %w", err)
	}
	labels := map[string]*MIPLabel{}
	for _, p := range props.Properties {
		if !strings.HasPrefix(p.Name, "MSIP_Label_") {
			continue
		}
		parts := strings.SplitN(p.Name, "_", 4)
		if len(parts) < 4 {
			continue
		}
		guid := parts[2]
		field := parts[3]
		lbl, ok := labels[guid]
		if !ok {
			lbl = &MIPLabel{LabelID: guid}
			labels[guid] = lbl
		}
		val := p.Lpwstr
		if val == "" {
			val = p.Value
		}
		switch field {
		case "Enabled":
			lbl.Enabled = strings.EqualFold(val, "true")
		case "SiteId":
			// stored for future use; no struct field yet
		case "SetDate":
			// stored for future use
		case "Name":
			lbl.Sensitivity = val
		}
	}
	var out []MIPLabel
	for _, l := range labels {
		if l.Enabled {
			out = append(out, *l)
		}
	}
	return out, nil
}

// readFromHeaders scans raw email bytes for
// X-MS-InformationProtection headers.
func (r *MIPReader) readFromHeaders(content []byte) ([]MIPLabel, error) {
	var labels []MIPLabel
	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			break // RFC 5322 header/body boundary
		}
		if strings.HasPrefix(strings.ToLower(line), "x-ms-informationprotection-label:") {
			val := strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
			labels = append(labels, MIPLabel{
				LabelID:     val,
				Sensitivity: val,
				Enabled:     true,
			})
		}
	}
	return labels, nil
}
