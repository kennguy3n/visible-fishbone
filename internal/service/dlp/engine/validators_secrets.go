package engine

import (
	"crypto/sha256"
	"strings"

	"golang.org/x/crypto/sha3"
)

// Crypto-wallet + AI-provider/SaaS credential validators.
//
// Like the national-ID check-digit validators, these confirm a span
// the regex layer matched is structurally a real wallet address or
// vendor credential — its checksum holds, or its exact prefix /
// charset / length is satisfied — rather than a same-shaped random
// run. They are the false-positive suppressor for the wallet + secret
// detectors.
//
// Every validator here has a byte-identical twin in
// crates/sng-dlp/src/validators.rs (wallet helpers) so a rule authored
// once decides the same way on the endpoint and in the control-plane
// SWG.

// allTokenByte reports whether s is non-empty and every byte is in the
// URL-safe token charset [A-Za-z0-9_-]. Mirrors `all_token_byte`.
func allTokenByte(s string) bool {
	if len(s) == 0 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !urlSafeB64Byte(s[i]) {
			return false
		}
	}
	return true
}

// isHexByte reports whether c is an ASCII hex digit (0-9, a-f, A-F).
func isHexByte(c byte) bool {
	return asciiDigitByte(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

// isHexAlphaByte reports whether c is an alphabetic hex digit (a-f,
// A-F) — i.e. a character that carries an EIP-55 case bit.
func isHexAlphaByte(c byte) bool {
	return (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

// base58Decode decodes a Bitcoin base58 string to bytes (no checksum
// check). Returns ok=false on any character outside the Bitcoin
// alphabet. Mirrors `base58_decode`.
func base58Decode(s string) ([]byte, bool) {
	const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	if len(s) == 0 {
		return nil, false
	}
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		idx := strings.IndexByte(alphabet, s[i])
		if idx < 0 {
			return nil, false
		}
		carry := uint32(idx)
		for j := range out {
			carry += uint32(out[j]) * 58
			out[j] = byte(carry & 0xff)
			carry >>= 8
		}
		for carry > 0 {
			out = append(out, byte(carry&0xff))
			carry >>= 8
		}
	}
	// Each leading '1' is a leading zero byte.
	for i := 0; i < len(s); i++ {
		if s[i] == '1' {
			out = append(out, 0)
		} else {
			break
		}
	}
	for l, r := 0, len(out)-1; l < r; l, r = l+1, r-1 {
		out[l], out[r] = out[r], out[l]
	}
	return out, true
}

// btcAddressBase58 validates a Bitcoin legacy address (P2PKH 1… /
// P2SH 3…): base58check with a 1-byte version (0x00 or 0x05), 20-byte
// hash and a 4-byte double-SHA-256 checksum. Mirrors
// `btc_address_base58`.
func btcAddressBase58(s string) bool {
	raw, ok := base58Decode(s)
	if !ok || len(raw) != 25 {
		return false
	}
	if raw[0] != 0x00 && raw[0] != 0x05 {
		return false
	}
	payload := raw[:21]
	checksum := raw[21:]
	first := sha256.Sum256(payload)
	second := sha256.Sum256(first[:])
	for i := 0; i < 4; i++ {
		if second[i] != checksum[i] {
			return false
		}
	}
	return true
}

// bech32Polymod is the BIP-173/350 checksum polymod over the
// HRP-expanded data values. Mirrors `bech32_polymod`.
func bech32Polymod(values []byte) uint32 {
	gen := [5]uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
	chk := uint32(1)
	for _, v := range values {
		top := chk >> 25
		chk = ((chk & 0x01ffffff) << 5) ^ uint32(v)
		for i := 0; i < 5; i++ {
			if (top>>uint(i))&1 == 1 {
				chk ^= gen[i]
			}
		}
	}
	return chk
}

// convertBits5to8 packs 5-bit groups into 8-bit bytes, returning
// ok=false if any padding bits are non-zero or more than 4 bits
// remain. Mirrors `convert_bits_5_to_8`.
func convertBits5to8(data []byte) ([]byte, bool) {
	var acc uint32
	var bits uint32
	out := make([]byte, 0, len(data))
	for _, value := range data {
		acc = (acc << 5) | uint32(value)
		bits += 5
		for bits >= 8 {
			bits -= 8
			out = append(out, byte((acc>>bits)&0xff))
		}
	}
	if bits > 4 || (acc<<(8-bits))&0xff != 0 {
		return nil, false
	}
	return out, true
}

// btcAddressBech32 validates a Bitcoin SegWit address (bc1…): BIP-173
// bech32 (witness v0) or BIP-350 bech32m (v1-16) with the "bc"
// human-readable part, the 30-bit checksum, the witness version, and a
// 2-40-byte program (20/32 for v0). Lowercase only. Mirrors
// `btc_address_bech32`.
func btcAddressBech32(s string) bool {
	const charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
	dataPart, ok := strings.CutPrefix(s, "bc1")
	if !ok {
		return false
	}
	// Need version (1) + one program group + checksum (6); a real
	// address is >= 11 data symbols, so this only guards the slice.
	if len(dataPart) < 8 || len(s) > 90 {
		return false
	}
	values := make([]byte, 0, len(dataPart))
	for i := 0; i < len(dataPart); i++ {
		pos := strings.IndexByte(charset, dataPart[i])
		if pos < 0 {
			return false
		}
		values = append(values, byte(pos))
	}
	// Expand HRP "bc": high bits, separator 0, low bits.
	hrp := []byte{'b', 'c'}
	combined := make([]byte, 0, len(hrp)*2+1+len(values))
	for _, c := range hrp {
		combined = append(combined, c>>5)
	}
	combined = append(combined, 0)
	for _, c := range hrp {
		combined = append(combined, c&0x1f)
	}
	combined = append(combined, values...)
	residual := bech32Polymod(combined)
	version := values[0]
	expected := uint32(1)
	if version != 0 {
		expected = 0x2bc830a3
	}
	if residual != expected || version > 16 {
		return false
	}
	program5 := values[1 : len(values)-6]
	program, ok := convertBits5to8(program5)
	if !ok {
		return false
	}
	if len(program) < 2 || len(program) > 40 {
		return false
	}
	if version == 0 && len(program) != 20 && len(program) != 32 {
		return false
	}
	return true
}

// ethAddress validates an Ethereum address: 0x + 40 hex with a valid
// EIP-55 mixed-case checksum. All-lowercase / all-uppercase addresses
// are not accepted — they carry no checksum to verify. Mirrors
// `eth_address`.
func ethAddress(s string) bool {
	var body string
	switch {
	case strings.HasPrefix(s, "0x"), strings.HasPrefix(s, "0X"):
		body = s[2:]
	default:
		return false
	}
	if len(body) != 40 {
		return false
	}
	hasAlpha := false
	for i := 0; i < len(body); i++ {
		if !isHexByte(body[i]) {
			return false
		}
		if isHexAlphaByte(body[i]) {
			hasAlpha = true
		}
	}
	if !hasAlpha {
		return false
	}
	lower := strings.ToLower(body)
	h := sha3.NewLegacyKeccak256()
	h.Write([]byte(lower))
	hash := h.Sum(nil)
	for i := 0; i < len(body); i++ {
		c := body[i]
		if !isHexAlphaByte(c) {
			continue
		}
		var nibble byte
		if i%2 == 0 {
			nibble = hash[i/2] >> 4
		} else {
			nibble = hash[i/2] & 0x0f
		}
		shouldUpper := nibble >= 8
		isUpper := c >= 'A' && c <= 'Z'
		if shouldUpper != isUpper {
			return false
		}
	}
	return true
}

// openAIAPIKey validates an OpenAI API key: legacy sk- + 48 base62, or
// project sk-proj- + >= 20 URL-safe chars. Rejects the Anthropic
// sk-ant- family (owned by anthropicAPIKey). Mirrors `openai_api_key`.
func openAIAPIKey(s string) bool {
	if body, ok := strings.CutPrefix(s, "sk-proj-"); ok {
		return len(body) >= 20 && allTokenByte(body)
	}
	if body, ok := strings.CutPrefix(s, "sk-"); ok {
		return len(body) == 48 && allASCIIAlnum(body)
	}
	return false
}

// anthropicAPIKey validates an Anthropic API key: sk-ant- + >= 20
// URL-safe chars (live form sk-ant-api03-…). Mirrors
// `anthropic_api_key`.
func anthropicAPIKey(s string) bool {
	body, ok := strings.CutPrefix(s, "sk-ant-")
	if !ok {
		return false
	}
	return len(body) >= 20 && allTokenByte(body)
}

// gitlabPAT validates a GitLab personal access token: glpat- + >= 20
// URL-safe chars. Mirrors `gitlab_pat`.
func gitlabPAT(s string) bool {
	body, ok := strings.CutPrefix(s, "glpat-")
	if !ok {
		return false
	}
	return len(body) >= 20 && allTokenByte(body)
}

// sendgridAPIKey validates a SendGrid API key: SG. + 22-char selector
// + . + 43-char secret, both URL-safe. Mirrors `sendgrid_api_key`.
func sendgridAPIKey(s string) bool {
	rest, ok := strings.CutPrefix(s, "SG.")
	if !ok {
		return false
	}
	parts := strings.Split(rest, ".")
	if len(parts) != 2 {
		return false
	}
	sel, secret := parts[0], parts[1]
	return len(sel) == 22 && allTokenByte(sel) && len(secret) == 43 && allTokenByte(secret)
}

// npmToken validates an npm access token: npm_ + 36 base62 chars.
// Mirrors `npm_token`.
func npmToken(s string) bool {
	body, ok := strings.CutPrefix(s, "npm_")
	if !ok {
		return false
	}
	return len(body) == 36 && allASCIIAlnum(body)
}

// twilioAPIKey validates a Twilio SID-form credential: AC (Account) or
// SK (API key) + 32 lowercase-hex chars, 34 total. Mirrors
// `twilio_api_key`.
func twilioAPIKey(s string) bool {
	if len(s) != 34 {
		return false
	}
	var body string
	switch {
	case strings.HasPrefix(s, "AC"), strings.HasPrefix(s, "SK"):
		body = s[2:]
	default:
		return false
	}
	if len(body) != 32 {
		return false
	}
	for i := 0; i < len(body); i++ {
		c := body[i]
		if !asciiDigitByte(c) && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
