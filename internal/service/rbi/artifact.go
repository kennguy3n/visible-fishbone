package rbi

import "strings"

// ArtifactKind enumerates the cross-boundary transfers an RBI session
// can mediate between the isolated render container and the user's
// endpoint. Every transfer is gated: the whole point of isolation is
// that bytes do not cross from the untrusted page to the endpoint (or
// vice versa) unless policy explicitly permits it.
type ArtifactKind string

const (
	// ArtifactClipboard is a clipboard copy/paste across the
	// isolation boundary.
	ArtifactClipboard ArtifactKind = "clipboard"
	// ArtifactFileDownload is a file the isolated page tried to
	// deliver to the endpoint.
	ArtifactFileDownload ArtifactKind = "file_download"
	// ArtifactFileUpload is a file the endpoint tried to send into
	// the isolated page.
	ArtifactFileUpload ArtifactKind = "file_upload"
)

// Valid reports whether k is a recognised artifact kind.
func (k ArtifactKind) Valid() bool {
	switch k {
	case ArtifactClipboard, ArtifactFileDownload, ArtifactFileUpload:
		return true
	default:
		return false
	}
}

// ArtifactDirection is the direction a transfer crosses the isolation
// boundary.
type ArtifactDirection string

const (
	// DirectionInbound is remote→endpoint (download / paste-in / the
	// remote page writing the endpoint clipboard).
	DirectionInbound ArtifactDirection = "inbound"
	// DirectionOutbound is endpoint→remote (upload / copy-out / the
	// endpoint writing the remote clipboard).
	DirectionOutbound ArtifactDirection = "outbound"
)

// Valid reports whether d is a recognised direction.
func (d ArtifactDirection) Valid() bool {
	return d == DirectionInbound || d == DirectionOutbound
}

// ArtifactPolicy is the operator-configurable gate for artifact
// transfers across the isolation boundary. The zero value DENIES
// everything: isolation defaults to sealing the container, and an
// operator opts specific transfers back in. This fail-closed default
// is deliberate — a misconfiguration leaves the boundary sealed, not
// open.
type ArtifactPolicy struct {
	// ClipboardInbound permits the remote page to write to the
	// endpoint clipboard (paste-in).
	ClipboardInbound bool
	// ClipboardOutbound permits the endpoint clipboard to be sent
	// into the remote page (copy-out).
	ClipboardOutbound bool
	// FileDownload permits files to be delivered from the remote
	// page to the endpoint.
	FileDownload bool
	// FileUpload permits files to be sent from the endpoint into the
	// remote page.
	FileUpload bool
}

// GateArtifact reports whether a transfer of the given kind and
// direction is permitted, and—when denied—a short machine-readable
// reason for audit. An unknown kind or direction is denied
// (fail-closed).
func (p ArtifactPolicy) GateArtifact(kind ArtifactKind, dir ArtifactDirection) (bool, string) {
	if !kind.Valid() {
		return false, "unknown_kind"
	}
	if !dir.Valid() {
		return false, "unknown_direction"
	}
	switch kind {
	case ArtifactClipboard:
		switch dir {
		case DirectionInbound:
			if p.ClipboardInbound {
				return true, ""
			}
			return false, "clipboard_inbound_disabled"
		case DirectionOutbound:
			if p.ClipboardOutbound {
				return true, ""
			}
			return false, "clipboard_outbound_disabled"
		}
	case ArtifactFileDownload:
		// A download is inherently remote→endpoint; an outbound
		// direction is a malformed request.
		if dir != DirectionInbound {
			return false, "download_must_be_inbound"
		}
		if p.FileDownload {
			return true, ""
		}
		return false, "file_download_disabled"
	case ArtifactFileUpload:
		// An upload is inherently endpoint→remote.
		if dir != DirectionOutbound {
			return false, "upload_must_be_outbound"
		}
		if p.FileUpload {
			return true, ""
		}
		return false, "file_upload_disabled"
	}
	return false, "denied"
}

// normalizeKind/normalizeDirection lower/trim raw caller input so the
// handler can pass through operator/agent-supplied strings.
func normalizeKind(s string) ArtifactKind {
	return ArtifactKind(strings.ToLower(strings.TrimSpace(s)))
}

func normalizeDirection(s string) ArtifactDirection {
	return ArtifactDirection(strings.ToLower(strings.TrimSpace(s)))
}
