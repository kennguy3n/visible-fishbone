package engine

import "unicode"

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
