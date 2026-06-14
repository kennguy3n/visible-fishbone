package engine

import (
	"encoding/json"
	"strings"
	"unicode"
)

// National-ID check-digit validators.
//
// These functions confirm that a string the regex layer matched is a
// structurally valid national identifier — its check digit (or date /
// prefix invariants) actually holds — rather than a same-shaped
// random digit run. They are the false-positive suppressor for the
// Asia + GCC PII detectors, the same role luhnValid plays for
// credit_card.
//
// Every validator here has a byte-identical twin in
// crates/sng-dlp/src/validators.rs; the two must stay in lock-step so
// a rule authored once decides the same way on the endpoint and in
// the control-plane SWG.
//
// Validators accept the raw matched span (which may carry the
// separators the pattern allowed — spaces and hyphens) and strip them
// internally, so the caller hands the matched text straight in.

// validatorFor resolves a builtin pattern name to the validator that
// confirms a hit is a real identifier, or nil when the pattern has no
// validator and relies on regex shape + proximity context alone
// (Qatar QID, Bahrain CPR). Mirrors `validator_for` in classifier.rs.
func validatorFor(name string) func(string) bool {
	switch name {
	case "china_resident_id":
		return chinaResidentID
	case "japan_my_number":
		return japanMyNumber
	case "korea_rrn":
		return koreaRRN
	case "singapore_nric":
		return singaporeNRIC
	case "malaysia_mykad":
		return malaysiaMyKad
	case "thailand_id":
		return thailandID
	case "india_aadhaar":
		return indiaAadhaar
	case "india_pan":
		return indiaPAN
	case "uae_emirates_id":
		return uaeEmiratesID
	case "saudi_id":
		return saudiNationalID
	case "kuwait_civil_id":
		return kuwaitCivilID
	// WS5 jurisdiction breadth — twins in validators_ws5.go.
	case "ni_uk":
		return ukNINO
	case "uk_nhs":
		return ukNHS
	case "canada_sin":
		return canadaSIN
	case "tfn_au":
		return australiaTFN
	case "australia_medicare":
		return australiaMedicare
	case "germany_personalausweis":
		return germanyPersonalausweis
	case "france_insee":
		return franceINSEE
	case "brazil_cpf":
		return brazilCPF
	case "brazil_cnpj":
		return brazilCNPJ
	case "iban":
		return euIBAN
	case "eu_vat":
		return euVAT
	case "philippines_umid":
		return philippinesUMID
	case "indonesia_nik":
		return indonesiaNIK
	// WS-10c jurisdiction breadth — twins in validators_ws10c.go.
	case "ireland_ppsn":
		return irelandPPSN
	case "switzerland_ahv":
		return switzerlandAHV
	case "israel_id":
		return israelID
	case "romania_cnp":
		return romaniaCNP
	case "mexico_curp":
		return mexicoCURP
	// Secret / credential detectors — twins in validators.rs.
	case "private_key_block":
		return privateKeyBlock
	case "aws_access_key_id":
		return awsAccessKeyID
	case "google_api_key":
		return googleAPIKey
	case "github_token":
		return githubToken
	case "github_pat":
		return githubFineGrainedPAT
	case "slack_token":
		return slackToken
	case "stripe_secret_key":
		return stripeSecretKey
	case "jwt":
		return jwtToken
	default:
		return nil
	}
}

// digitsOf collects the decimal digits of s as values 0..9, ignoring
// any non-digit byte (separators, letters). Mirrors `digits`.
func digitsOf(s string) []int {
	d := make([]int, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] >= '0' && s[i] <= '9' {
			d = append(d, int(s[i]-'0'))
		}
	}
	return d
}

// luhnDigits runs the Luhn (mod-10) checksum over an exact digit
// slice with no length window, so it can back the fixed-width GCC
// identifiers (Emirates ID = 15, Saudi national ID = 10). Mirrors
// `luhn_digits`.
func luhnDigits(d []int) bool {
	if len(d) == 0 {
		return false
	}
	sum := 0
	double := false
	for i := len(d) - 1; i >= 0; i-- {
		v := d[i]
		if double {
			v *= 2
			if v > 9 {
				v -= 9
			}
		}
		sum += v
		double = !double
	}
	return sum%10 == 0
}

// validYMD reports whether (year, month, day) is a real Gregorian
// calendar date. Mirrors `valid_ymd`.
func validYMD(year, month, day int) bool {
	if month < 1 || month > 12 || day < 1 {
		return false
	}
	leap := (year%4 == 0 && year%100 != 0) || year%400 == 0
	var maxDay int
	switch month {
	case 1, 3, 5, 7, 8, 10, 12:
		maxDay = 31
	case 4, 6, 9, 11:
		maxDay = 30
	case 2:
		if leap {
			maxDay = 29
		} else {
			maxDay = 28
		}
	default:
		return false
	}
	return day <= maxDay
}

// nonSpaceRunes returns the runes of s with Unicode whitespace
// removed.
func nonSpaceRunes(s string) []rune {
	r := make([]rune, 0, len(s))
	for _, c := range s {
		if !unicode.IsSpace(c) {
			r = append(r, c)
		}
	}
	return r
}

// nonSpaceUpperRunes returns the runes of s with whitespace removed
// and ASCII letters upper-cased (matching Rust's
// `char::to_ascii_uppercase`).
func nonSpaceUpperRunes(s string) []rune {
	r := make([]rune, 0, len(s))
	for _, c := range s {
		if unicode.IsSpace(c) {
			continue
		}
		if c >= 'a' && c <= 'z' {
			c -= 'a' - 'A'
		}
		r = append(r, c)
	}
	return r
}

func isASCIILetter(r rune) bool {
	return (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z')
}

// chinaResidentID validates an 18-character China resident identity
// card (居民身份证): 17 digits plus a check character (digit or X),
// ISO 7064 MOD 11-2 over the 17 body digits, with a real YYYYMMDD DOB
// in positions 6..14.
func chinaResidentID(s string) bool {
	weights := [17]int{7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2}

	chars := nonSpaceRunes(s)
	if len(chars) != 18 {
		return false
	}
	body := make([]int, 17)
	for i := 0; i < 17; i++ {
		if chars[i] < '0' || chars[i] > '9' {
			return false
		}
		body[i] = int(chars[i] - '0')
	}
	year := body[6]*1000 + body[7]*100 + body[8]*10 + body[9]
	month := body[10]*10 + body[11]
	day := body[12]*10 + body[13]
	if year < 1900 || year > 2100 || !validYMD(year, month, day) {
		return false
	}
	sum := 0
	for i, w := range weights {
		sum += body[i] * w
	}
	expected := (12 - sum%11) % 11
	last := chars[17]
	var actual int
	switch {
	case last == 'X' || last == 'x':
		actual = 10
	case last >= '0' && last <= '9':
		actual = int(last - '0')
	default:
		return false
	}
	return expected == actual
}

// japanMyNumber validates a 12-digit Japan Individual Number
// (マイナンバー) with a MOD 11 check digit over the leading 11.
func japanMyNumber(s string) bool {
	d := digitsOf(s)
	if len(d) != 12 {
		return false
	}
	sum := 0
	for n := 1; n <= 11; n++ {
		p := d[11-n]
		var q int
		if n <= 6 {
			q = n + 1
		} else {
			q = n - 5
		}
		sum += p * q
	}
	rem := sum % 11
	expected := 0
	if rem > 1 {
		expected = 11 - rem
	}
	return d[11] == expected
}

// koreaRRN validates a 13-digit South Korea Resident Registration
// Number (주민등록번호): YYMMDD, gender/century digit, 5-digit serial,
// and a weighted MOD 11 check digit.
func koreaRRN(s string) bool {
	weights := [12]int{2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5}

	d := digitsOf(s)
	if len(d) != 13 {
		return false
	}
	var yearPrefix int
	switch d[6] {
	case 1, 2, 5, 6:
		yearPrefix = 1900
	case 3, 4, 7, 8:
		yearPrefix = 2000
	case 0, 9:
		yearPrefix = 1800
	default:
		return false
	}
	year := yearPrefix + d[0]*10 + d[1]
	month := d[2]*10 + d[3]
	day := d[4]*10 + d[5]
	if !validYMD(year, month, day) {
		return false
	}
	sum := 0
	for i, w := range weights {
		sum += d[i] * w
	}
	expected := (11 - sum%11) % 10
	return d[12] == expected
}

// singaporeNRIC validates a Singapore NRIC / FIN: a prefix letter
// (S/T/F/G/M), 7 digits, and a check letter from a per-series table
// indexed by a weighted sum of the 7 digits.
func singaporeNRIC(s string) bool {
	weights := [7]int{2, 7, 6, 5, 4, 3, 2}

	chars := nonSpaceUpperRunes(s)
	if len(chars) != 9 {
		return false
	}
	prefix := chars[0]
	check := chars[8]
	nums := make([]int, 7)
	for i := 0; i < 7; i++ {
		c := chars[1+i]
		if c < '0' || c > '9' {
			return false
		}
		nums[i] = int(c - '0')
	}
	sum := 0
	for i, w := range weights {
		sum += nums[i] * w
	}
	// Series offset: T/G shift by 4, M (post-2021 FIN) by 3.
	switch prefix {
	case 'T', 'G':
		sum += 4
	case 'M':
		sum += 3
	case 'S', 'F':
	default:
		return false
	}
	var expected rune
	switch prefix {
	case 'S', 'T':
		table := [11]rune{'J', 'Z', 'I', 'H', 'G', 'F', 'E', 'D', 'C', 'B', 'A'}
		expected = table[sum%11]
	case 'F', 'G':
		table := [11]rune{'X', 'W', 'U', 'T', 'R', 'Q', 'P', 'N', 'M', 'L', 'K'}
		expected = table[sum%11]
	case 'M':
		table := [11]rune{'K', 'L', 'J', 'N', 'P', 'Q', 'R', 'T', 'U', 'W', 'X'}
		expected = table[10-sum%11]
	default:
		return false
	}
	return expected == check
}

// malaysiaStateOK reports whether code is a recognised MyKad
// place-of-birth (state) code. Codes 60–81 are reserved / unused.
func malaysiaStateOK(code int) bool {
	return (code >= 1 && code <= 59) || (code >= 82 && code <= 99)
}

// malaysiaMyKad validates a 12-digit Malaysia MyKad: YYMMDD, a
// 2-digit place-of-birth code, then a 4-digit serial. There is no
// check digit, so validity rests on a real DOB and a known state
// code.
func malaysiaMyKad(s string) bool {
	d := digitsOf(s)
	if len(d) != 12 {
		return false
	}
	yy := d[0]*10 + d[1]
	month := d[2]*10 + d[3]
	day := d[4]*10 + d[5]
	if !validYMD(2000+yy, month, day) {
		return false
	}
	state := d[6]*10 + d[7]
	return malaysiaStateOK(state)
}

// thailandID validates a 13-digit Thailand national ID with a
// weighted MOD 11 check digit (weights 13..=2 over the leading 12).
func thailandID(s string) bool {
	weights := [12]int{13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2}

	d := digitsOf(s)
	if len(d) != 13 {
		return false
	}
	sum := 0
	for i, w := range weights {
		sum += d[i] * w
	}
	expected := (11 - sum%11) % 10
	return d[12] == expected
}

// indiaAadhaar validates a 12-digit India Aadhaar guarded by a
// Verhoeff check digit; the leading digit is never 0 or 1.
func indiaAadhaar(s string) bool {
	d := digitsOf(s)
	if len(d) != 12 || d[0] < 2 {
		return false
	}
	return verhoeffValid(d)
}

// indiaPAN validates an India PAN: 5 letters, 4 digits, 1 letter,
// where the 4th letter encodes the holder type.
func indiaPAN(s string) bool {
	c := nonSpaceUpperRunes(s)
	if len(c) != 10 {
		return false
	}
	for i := 0; i < 5; i++ {
		if !isASCIILetter(c[i]) {
			return false
		}
	}
	for i := 5; i < 9; i++ {
		if c[i] < '0' || c[i] > '9' {
			return false
		}
	}
	if !isASCIILetter(c[9]) {
		return false
	}
	switch c[3] {
	case 'A', 'B', 'C', 'F', 'G', 'H', 'J', 'L', 'P', 'T', 'E', 'K':
		return true
	default:
		return false
	}
}

// uaeEmiratesID validates a 15-digit UAE Emirates ID beginning 784
// with a Luhn check over all 15 digits.
func uaeEmiratesID(s string) bool {
	d := digitsOf(s)
	if len(d) != 15 {
		return false
	}
	if d[0] != 7 || d[1] != 8 || d[2] != 4 {
		return false
	}
	return luhnDigits(d)
}

// saudiNationalID validates a 10-digit Saudi national / Iqama ID
// beginning 1 (citizen) or 2 (resident) with a Luhn check over all
// 10 digits.
func saudiNationalID(s string) bool {
	d := digitsOf(s)
	if len(d) != 10 {
		return false
	}
	if d[0] != 1 && d[0] != 2 {
		return false
	}
	return luhnDigits(d)
}

// kuwaitCivilID validates a 12-digit Kuwait Civil ID: a century
// digit, YYMMDD, a 3-digit serial, and a weighted MOD 11 check digit.
func kuwaitCivilID(s string) bool {
	weights := [11]int{2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2}

	d := digitsOf(s)
	if len(d) != 12 {
		return false
	}
	var century int
	switch d[0] {
	case 1:
		century = 1800
	case 2:
		century = 1900
	case 3:
		century = 2000
	default:
		return false
	}
	year := century + d[1]*10 + d[2]
	month := d[3]*10 + d[4]
	day := d[5]*10 + d[6]
	if !validYMD(year, month, day) {
		return false
	}
	sum := 0
	for i, w := range weights {
		sum += d[i] * w
	}
	check := 11 - sum%11
	return check < 10 && d[11] == check
}

// verhoeffValid runs the Verhoeff checksum (dihedral group D5) over a
// digit slice whose final element is the check digit. Backs
// indiaAadhaar.
func verhoeffValid(d []int) bool {
	mul := [10][10]int{
		{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
		{1, 2, 3, 4, 0, 6, 7, 8, 9, 5},
		{2, 3, 4, 0, 1, 7, 8, 9, 5, 6},
		{3, 4, 0, 1, 2, 8, 9, 5, 6, 7},
		{4, 0, 1, 2, 3, 9, 5, 6, 7, 8},
		{5, 9, 8, 7, 6, 0, 4, 3, 2, 1},
		{6, 5, 9, 8, 7, 1, 0, 4, 3, 2},
		{7, 6, 5, 9, 8, 2, 1, 0, 4, 3},
		{8, 7, 6, 5, 9, 3, 2, 1, 0, 4},
		{9, 8, 7, 6, 5, 4, 3, 2, 1, 0},
	}
	perm := [8][10]int{
		{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
		{1, 5, 7, 6, 2, 8, 3, 0, 9, 4},
		{5, 8, 0, 3, 7, 9, 6, 1, 4, 2},
		{8, 9, 1, 6, 0, 4, 3, 5, 2, 7},
		{9, 4, 5, 3, 1, 2, 6, 8, 7, 0},
		{4, 2, 8, 6, 5, 7, 3, 9, 0, 1},
		{2, 7, 9, 3, 8, 0, 6, 4, 1, 5},
		{7, 0, 4, 6, 9, 1, 3, 2, 5, 8},
	}
	c := 0
	// Fold from the least-significant digit (the check digit) up.
	for i := 0; i < len(d); i++ {
		digit := d[len(d)-1-i]
		c = mul[c][perm[i%8][digit]]
	}
	return c == 0
}

// --- Secret / credential validators ---
//
// These confirm a regex hit on a high-entropy credential is the real
// artifact (exact prefix + charset + length, or a decodable inner
// structure) rather than same-shaped noise — the false-positive
// suppressor role the national-ID check digits play above. Each has a
// byte-identical twin in crates/sng-dlp/src/validators.rs so a
// secrets-credentials rule decides identically on the endpoint and in
// the control plane.

// Byte character-class predicates for the secret validators. They are
// expressed positively (rather than as negated disjunctions in each
// scan loop) so the per-byte rejection reads `if !classByte(c)` — one
// named class per credential charset, mirroring the Rust
// `u8::is_ascii_*` helpers.
func asciiDigitByte(c byte) bool { return c >= '0' && c <= '9' }
func asciiUpperByte(c byte) bool { return c >= 'A' && c <= 'Z' }
func asciiLowerByte(c byte) bool { return c >= 'a' && c <= 'z' }
func asciiAlnumByte(c byte) bool {
	return asciiDigitByte(c) || asciiUpperByte(c) || asciiLowerByte(c)
}

// awsKeyBodyByte is the AWS access-key body charset: uppercase base32
// (A-Z, 0-9).
func awsKeyBodyByte(c byte) bool { return asciiUpperByte(c) || asciiDigitByte(c) }

// urlSafeB64Byte is the url-safe base64 charset (A-Z, a-z, 0-9, -, _),
// used by Google API keys.
func urlSafeB64Byte(c byte) bool { return asciiAlnumByte(c) || c == '-' || c == '_' }

// alnumUnderscoreByte is the GitHub fine-grained PAT body charset
// ([A-Za-z0-9_]).
func alnumUnderscoreByte(c byte) bool { return asciiAlnumByte(c) || c == '_' }

// alnumHyphenByte is the Slack token body charset ([A-Za-z0-9-]).
func alnumHyphenByte(c byte) bool { return asciiAlnumByte(c) || c == '-' }

// allASCIIAlnum reports whether s is non-empty and every byte is an
// ASCII alphanumeric. Mirrors `all_ascii_alnum`.
func allASCIIAlnum(s string) bool {
	if len(s) == 0 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !asciiAlnumByte(s[i]) {
			return false
		}
	}
	return true
}

// isASCIIWhitespace matches Rust's u8::is_ascii_whitespace exactly:
// space, tab, newline, carriage return, and form feed.
func isASCIIWhitespace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r' || b == '\f'
}

// awsAccessKeyID validates an AWS access key ID: AKIA (long-term) or
// ASIA (temporary STS) followed by exactly 16 uppercase-base32
// characters (A-Z, 0-9), 20 total. Mirrors `aws_access_key_id`.
func awsAccessKeyID(s string) bool {
	if len(s) != 20 {
		return false
	}
	if !strings.HasPrefix(s, "AKIA") && !strings.HasPrefix(s, "ASIA") {
		return false
	}
	body := s[4:]
	for i := 0; i < len(body); i++ {
		if !awsKeyBodyByte(body[i]) {
			return false
		}
	}
	return true
}

// googleAPIKey validates a Google API key: AIza followed by 35
// url-safe-base64 characters (A-Z, a-z, 0-9, -, _), 39 total. Mirrors
// `google_api_key`.
func googleAPIKey(s string) bool {
	if !strings.HasPrefix(s, "AIza") {
		return false
	}
	body := s[4:]
	if len(body) != 35 {
		return false
	}
	for i := 0; i < len(body); i++ {
		if !urlSafeB64Byte(body[i]) {
			return false
		}
	}
	return true
}

// githubToken validates a GitHub token: a ghp_/gho_/ghu_/ghs_/ghr_
// prefix followed by 36 alphanumerics. Mirrors `github_token`.
func githubToken(s string) bool {
	i := strings.IndexByte(s, '_')
	if i < 0 {
		return false
	}
	prefix, body := s[:i], s[i+1:]
	switch prefix {
	case "ghp", "gho", "ghu", "ghs", "ghr":
	default:
		return false
	}
	return len(body) == 36 && allASCIIAlnum(body)
}

// githubFineGrainedPAT validates a GitHub fine-grained PAT:
// github_pat_ followed by 82 characters of [A-Za-z0-9_]. Mirrors
// `github_fine_grained_pat`.
func githubFineGrainedPAT(s string) bool {
	const prefix = "github_pat_"
	if !strings.HasPrefix(s, prefix) {
		return false
	}
	body := s[len(prefix):]
	if len(body) != 82 {
		return false
	}
	for i := 0; i < len(body); i++ {
		if !alnumUnderscoreByte(body[i]) {
			return false
		}
	}
	return true
}

// slackToken validates a Slack token: an xoxb-/xoxa-/xoxp-/xoxr-/xoxs-
// prefix followed by a hyphen-separated alphanumeric body of at least
// 10 characters. Mirrors `slack_token`.
func slackToken(s string) bool {
	var body string
	switch {
	case strings.HasPrefix(s, "xoxb-"),
		strings.HasPrefix(s, "xoxa-"),
		strings.HasPrefix(s, "xoxp-"),
		strings.HasPrefix(s, "xoxr-"),
		strings.HasPrefix(s, "xoxs-"):
		body = s[5:]
	default:
		return false
	}
	if len(body) < 10 {
		return false
	}
	for i := 0; i < len(body); i++ {
		if !alnumHyphenByte(body[i]) {
			return false
		}
	}
	return true
}

// stripeSecretKey validates a Stripe secret/restricted key: sk_live_
// or rk_live_ followed by at least 16 alphanumerics. Only live keys
// are matched — sk_test_ keys are not production credentials. Mirrors
// `stripe_secret_key`.
func stripeSecretKey(s string) bool {
	var body string
	switch {
	case strings.HasPrefix(s, "sk_live_"), strings.HasPrefix(s, "rk_live_"):
		body = s[8:]
	default:
		return false
	}
	return len(body) >= 16 && allASCIIAlnum(body)
}

// privateKeyBlock confirms the matched span carries both the
// BEGIN/END PRIVATE KEY armor and a non-trivial body (>= 64
// non-whitespace bytes) between them, so an empty/truncated
// placeholder block is not flagged as a live key. Mirrors
// `private_key_block`.
func privateKeyBlock(s string) bool {
	const marker = "PRIVATE KEY-----"
	begin := strings.Index(s, marker)
	if begin < 0 {
		return false
	}
	rest := s[begin+len(marker):]
	endRel := strings.Index(rest, "-----END")
	if endRel < 0 {
		return false
	}
	body := rest[:endRel]
	count := 0
	for i := 0; i < len(body); i++ {
		if !isASCIIWhitespace(body[i]) {
			count++
		}
	}
	return count >= 64
}

// base64urlDecode decodes a base64url segment (RFC 4648 §5, no
// padding) into bytes, returning ok=false on any invalid character or
// trailing-bit remainder. Hand-rolled to stay byte-identical to the
// Rust `base64url_decode`, which mirrors this `RawURLEncoding`
// behaviour so the JWT header check decides the same on both sides.
func base64urlDecode(seg string) ([]byte, bool) {
	val := func(b byte) (byte, bool) {
		switch {
		case b >= 'A' && b <= 'Z':
			return b - 'A', true
		case b >= 'a' && b <= 'z':
			return b - 'a' + 26, true
		case b >= '0' && b <= '9':
			return b - '0' + 52, true
		case b == '-':
			return 62, true
		case b == '_':
			return 63, true
		default:
			return 0, false
		}
	}
	if len(seg)%4 == 1 {
		return nil, false
	}
	out := make([]byte, 0, len(seg)*3/4)
	var acc uint32
	var bits uint32
	for i := 0; i < len(seg); i++ {
		v, ok := val(seg[i])
		if !ok {
			return nil, false
		}
		acc = (acc << 6) | uint32(v)
		bits += 6
		if bits >= 8 {
			bits -= 8
			out = append(out, byte((acc>>bits)&0xFF))
		}
	}
	if acc&((1<<bits)-1) != 0 {
		return nil, false
	}
	return out, true
}

// jwtToken validates a JSON Web Token: three base64url segments joined
// by '.'. The header (segment 0) must decode to a JSON object carrying
// the mandatory "alg" field — which separates a real JWT from any
// other dotted base64url run. Mirrors `jwt`.
func jwtToken(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return false
	}
	header, ok := base64urlDecode(parts[0])
	if !ok {
		return false
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(header, &obj); err != nil {
		return false
	}
	_, has := obj["alg"]
	return has
}
