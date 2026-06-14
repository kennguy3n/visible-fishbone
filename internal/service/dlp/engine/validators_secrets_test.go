package engine

import (
	"strings"
	"testing"
)

// These mirror the Rust unit tests in validators.rs so the wallet and
// credential validators are confirmed byte-identical across the
// endpoint (Rust) and control-plane (Go) implementations.

func TestBTCBase58Twin(t *testing.T) {
	good := []string{
		"1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", // genesis P2PKH
		"3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy", // P2SH
	}
	for _, s := range good {
		if !btcAddressBase58(s) {
			t.Errorf("btcAddressBase58(%q) = false, want true", s)
		}
	}
	bad := []string{
		"1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb", // flipped checksum char
		"1abcdef",                            // far too short
		"1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf0O", // 0/O not in alphabet
	}
	for _, s := range bad {
		if btcAddressBase58(s) {
			t.Errorf("btcAddressBase58(%q) = true, want false", s)
		}
	}
}

func TestBTCBech32Twin(t *testing.T) {
	if !btcAddressBech32("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4") {
		t.Error("valid BIP-173 P2WPKH rejected")
	}
	bad := []string{
		"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5", // corrupted
		"tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx", // wrong HRP
	}
	for _, s := range bad {
		if btcAddressBech32(s) {
			t.Errorf("btcAddressBech32(%q) = true, want false", s)
		}
	}
}

func TestETHEIP55Twin(t *testing.T) {
	good := []string{
		"0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
		"0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
	}
	for _, s := range good {
		if !ethAddress(s) {
			t.Errorf("ethAddress(%q) = false, want true", s)
		}
	}
	bad := []string{
		"0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed", // all-lowercase, no checksum
		"0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeD", // one letter mis-cased
		"0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAe",  // 39 hex
		"5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",   // missing prefix
	}
	for _, s := range bad {
		if ethAddress(s) {
			t.Errorf("ethAddress(%q) = true, want false", s)
		}
	}
}

func TestOpenAITwin(t *testing.T) {
	if !openAIAPIKey("sk-" + strings.Repeat("a", 48)) {
		t.Error("legacy OpenAI key rejected")
	}
	if !openAIAPIKey("sk-proj-" + strings.Repeat("Ab9_-", 5)) {
		t.Error("project OpenAI key rejected")
	}
	if openAIAPIKey("sk-" + strings.Repeat("a", 47)) {
		t.Error("47-char legacy body accepted")
	}
	if openAIAPIKey("sk-ant-" + strings.Repeat("a", 30)) {
		t.Error("sk-ant- key must not be OpenAI")
	}
}

func TestAnthropicGitLabTwin(t *testing.T) {
	if !anthropicAPIKey("sk-ant-api03-" + strings.Repeat("Ab9_-", 6)) {
		t.Error("Anthropic key rejected")
	}
	if anthropicAPIKey("sk-ant-" + strings.Repeat("a", 10)) {
		t.Error("short Anthropic body accepted")
	}
	if !gitlabPAT("glpat-" + strings.Repeat("Ab9_-", 5)) {
		t.Error("GitLab PAT rejected")
	}
	if gitlabPAT("glpat-" + strings.Repeat("a", 10)) {
		t.Error("short GitLab body accepted")
	}
}

func TestSendGridTwin(t *testing.T) {
	sel := strings.Repeat("A", 22)
	secret := strings.Repeat("B", 43)
	if !sendgridAPIKey("SG." + sel + "." + secret) {
		t.Error("valid SendGrid key rejected")
	}
	if sendgridAPIKey("SG." + strings.Repeat("A", 21) + "." + secret) {
		t.Error("wrong selector length accepted")
	}
	if sendgridAPIKey("SG." + sel + "." + strings.Repeat("B", 42)) {
		t.Error("wrong secret length accepted")
	}
	if sendgridAPIKey("SG." + sel) {
		t.Error("single-segment accepted")
	}
}

func TestNPMTwilioTwin(t *testing.T) {
	if !npmToken("npm_" + strings.Repeat("a", 36)) {
		t.Error("npm token rejected")
	}
	if npmToken("npm_" + strings.Repeat("a", 35)) {
		t.Error("35-char npm body accepted")
	}
	if !twilioAPIKey("AC" + strings.Repeat("0123456789abcdef", 2)) {
		t.Error("Twilio AC SID rejected")
	}
	if !twilioAPIKey("SK" + strings.Repeat("fedcba9876543210", 2)) {
		t.Error("Twilio SK SID rejected")
	}
	if twilioAPIKey("AC" + strings.Repeat("0", 31)) {
		t.Error("31-char body accepted")
	}
	if twilioAPIKey("AC" + strings.Repeat("0123456789ABCDEF", 2)) {
		t.Error("uppercase hex accepted")
	}
}
