package engine

import (
	"strconv"
	"strings"
	"unicode"
)

// Workstream-5 jurisdiction validators.
//
// Each function here is the byte-identical Go twin of a validator in
// crates/sng-dlp/src/detectors/, extending the national-ID coverage in
// validators.go to the UK, Canada, Australia, Germany, France, Brazil,
// the EU (IBAN + VAT) and Indonesia / Philippines. The endpoint
// (Rust) and the control-plane SWG (Go) must decide identically, so
// the algorithms below mirror the Rust detectors exactly — same
// weights, same separators stripped, same accept/reject edges.

// alnumValue maps an alphanumeric document character to its value:
// digits to 0..9 and letters A..Z to 10..35. Mirrors `alnum_value`.
func alnumValue(r rune) (int, bool) {
	switch {
	case r >= '0' && r <= '9':
		return int(r - '0'), true
	case r >= 'A' && r <= 'Z':
		return int(r-'A') + 10, true
	default:
		return 0, false
	}
}

// allSameDigits reports whether every digit in d is identical. Mirrors
// `all_same`.
func allSameDigits(d []int) bool {
	for i := 1; i < len(d); i++ {
		if d[i] != d[0] {
			return false
		}
	}
	return true
}

// ukNINO validates a UK National Insurance Number: two prefix letters,
// six digits and an A–D suffix, subject to HMRC's allocation rules.
func ukNINO(s string) bool {
	c := nonSpaceUpperRunes(s)
	if len(c) != 9 {
		return false
	}
	if !isASCIILetter(c[0]) || !isASCIILetter(c[1]) {
		return false
	}
	for i := 2; i < 8; i++ {
		if c[i] < '0' || c[i] > '9' {
			return false
		}
	}
	switch c[0] {
	case 'D', 'F', 'I', 'Q', 'U', 'V':
		return false
	}
	switch c[1] {
	case 'D', 'F', 'I', 'O', 'Q', 'U', 'V':
		return false
	}
	switch string(c[0:2]) {
	case "BG", "GB", "KN", "NK", "NT", "TN", "ZZ":
		return false
	}
	switch c[8] {
	case 'A', 'B', 'C', 'D':
		return true
	}
	return false
}

// ukNHS validates a UK NHS number: ten digits with a weighted
// modulus-11 check digit (a computed value of 10 is never issued).
func ukNHS(s string) bool {
	d := digitsOf(s)
	if len(d) != 10 {
		return false
	}
	sum := 0
	for i := 0; i < 9; i++ {
		sum += d[i] * (10 - i)
	}
	check := (11 - sum%11) % 11
	return check != 10 && d[9] == check
}

// canadaSIN validates a Canada Social Insurance Number: nine digits
// with a Luhn check and a non-zero leading digit.
func canadaSIN(s string) bool {
	d := digitsOf(s)
	if len(d) != 9 {
		return false
	}
	if d[0] == 0 {
		return false
	}
	return luhnDigits(d)
}

// australiaTFN validates an Australia Tax File Number: eight (legacy)
// or nine digits whose weighted sum is divisible by 11.
func australiaTFN(s string) bool {
	d := digitsOf(s)
	var weights []int
	switch len(d) {
	case 9:
		weights = []int{1, 4, 3, 7, 5, 8, 6, 9, 10}
	case 8:
		weights = []int{10, 7, 8, 4, 6, 3, 5, 1}
	default:
		return false
	}
	sum := 0
	for i, w := range weights {
		sum += d[i] * w
	}
	return sum%11 == 0
}

// australiaMedicare validates an Australia Medicare card number: ten
// digits where the ninth is a weighted modulus-10 check over the first
// eight and the first digit is in 2..=6.
func australiaMedicare(s string) bool {
	d := digitsOf(s)
	if len(d) != 10 {
		return false
	}
	if d[0] < 2 || d[0] > 6 {
		return false
	}
	weights := [8]int{1, 3, 7, 9, 1, 3, 7, 9}
	sum := 0
	for i, w := range weights {
		sum += d[i] * w
	}
	return d[8] == sum%10
}

// germanyPersonalausweis validates a Germany Personalausweis number:
// nine alphanumeric document characters plus a decimal check digit,
// weight pattern 7,3,1 modulo 10.
func germanyPersonalausweis(s string) bool {
	c := nonSpaceUpperRunes(s)
	if len(c) != 10 {
		return false
	}
	weights := [3]int{7, 3, 1}
	sum := 0
	for i := 0; i < 9; i++ {
		v, ok := alnumValue(c[i])
		if !ok {
			return false
		}
		sum += v * weights[i%3]
	}
	if c[9] < '0' || c[9] > '9' {
		return false
	}
	return sum%10 == int(c[9]-'0')
}

// plausibleMonthFR reports whether m is a NIR-permitted month: the
// calendar months plus the fictitious months 20, 30..=42, 50, 99.
func plausibleMonthFR(m int) bool {
	switch {
	case m >= 1 && m <= 12:
		return true
	case m == 20 || m == 50 || m == 99:
		return true
	case m >= 30 && m <= 42:
		return true
	default:
		return false
	}
}

// franceINSEE validates a France INSEE number (NIR): a 13-character
// body plus a two-digit control key (97 − body mod 97), folding the
// Corsican department codes 2A/2B into the numeric body.
func franceINSEE(s string) bool {
	c := make([]rune, 0, len(s))
	for _, r := range s {
		if unicode.IsSpace(r) || r == '-' {
			continue
		}
		if r >= 'a' && r <= 'z' {
			r -= 'a' - 'A'
		}
		c = append(c, r)
	}
	if len(c) != 15 {
		return false
	}
	if c[0] < '0' || c[0] > '9' {
		return false
	}
	sex := int(c[0] - '0')
	if sex < 1 || sex > 4 {
		return false
	}
	if c[3] < '0' || c[3] > '9' || c[4] < '0' || c[4] > '9' {
		return false
	}
	month := int(c[3]-'0')*10 + int(c[4]-'0')
	if !plausibleMonthFR(month) {
		return false
	}
	var body strings.Builder
	var corsica int64
	for i := 0; i < 13; i++ {
		ch := c[i]
		switch {
		case ch >= '0' && ch <= '9':
			body.WriteRune(ch)
		case ch == 'A' && i == 6:
			body.WriteByte('0')
			corsica = 1_000_000
		case ch == 'B' && i == 6:
			body.WriteByte('0')
			corsica = 2_000_000
		default:
			return false
		}
	}
	n, err := strconv.ParseInt(body.String(), 10, 64)
	if err != nil {
		return false
	}
	if n < corsica {
		return false
	}
	n -= corsica
	if c[13] < '0' || c[13] > '9' || c[14] < '0' || c[14] > '9' {
		return false
	}
	key := int64(c[13]-'0')*10 + int64(c[14]-'0')
	if key < 1 || key > 97 {
		return false
	}
	return 97-(n%97) == key
}

// brMod11 computes a Brazilian modulus-11 check digit over body with
// descending weights from startWeight; a remainder < 2 yields 0.
// Mirrors `mod11_check`.
func brMod11(body []int, startWeight int) int {
	sum := 0
	for i, d := range body {
		sum += d * (startWeight - i)
	}
	if r := sum % 11; r >= 2 {
		return 11 - r
	}
	return 0
}

// brazilCPF validates a Brazil CPF: eleven digits with two trailing
// modulus-11 check digits; repdigit numbers are rejected.
func brazilCPF(s string) bool {
	d := digitsOf(s)
	if len(d) != 11 || allSameDigits(d) {
		return false
	}
	return d[9] == brMod11(d[:9], 10) && d[10] == brMod11(d[:10], 11)
}

// cnpjCheck computes a CNPJ check digit over body with the fixed
// per-position weights. Mirrors `cnpj_check`.
func cnpjCheck(body, weights []int) int {
	sum := 0
	for i, w := range weights {
		sum += body[i] * w
	}
	if r := sum % 11; r >= 2 {
		return 11 - r
	}
	return 0
}

// brazilCNPJ validates a Brazil CNPJ: fourteen digits with two
// trailing modulus-11 check digits; repdigit numbers are rejected.
func brazilCNPJ(s string) bool {
	d := digitsOf(s)
	if len(d) != 14 || allSameDigits(d) {
		return false
	}
	w1 := []int{5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2}
	w2 := []int{6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2}
	return d[12] == cnpjCheck(d[:12], w1) && d[13] == cnpjCheck(d[:13], w2)
}

// euIBAN validates an IBAN (ISO 13616) via the mod-97 check, computing
// the modulus incrementally so no big-integer math is needed.
func euIBAN(s string) bool {
	c := nonSpaceUpperRunes(s)
	if len(c) < 15 || len(c) > 34 {
		return false
	}
	if !isASCIILetter(c[0]) || !isASCIILetter(c[1]) {
		return false
	}
	if c[2] < '0' || c[2] > '9' || c[3] < '0' || c[3] > '9' {
		return false
	}
	var rem int64
	step := func(r rune) bool {
		switch {
		case r >= '0' && r <= '9':
			rem = (rem*10 + int64(r-'0')) % 97
		case r >= 'A' && r <= 'Z':
			rem = (rem*100 + int64(r-'A') + 10) % 97
		default:
			return false
		}
		return true
	}
	for i := 4; i < len(c); i++ {
		if !step(c[i]) {
			return false
		}
	}
	for i := 0; i < 4; i++ {
		if !step(c[i]) {
			return false
		}
	}
	return rem == 1
}

// philippinesUMID validates a Philippines UMID / CRN: twelve digits,
// non-zero leading digit, not a single repeated digit.
func philippinesUMID(s string) bool {
	d := digitsOf(s)
	if len(d) != 12 {
		return false
	}
	if d[0] == 0 {
		return false
	}
	return !allSameDigits(d)
}

// indonesiaNIK validates an Indonesia NIK (KTP): sixteen digits with a
// region prefix, an embedded date of birth (day +40 for female
// holders) and a non-zero serial.
func indonesiaNIK(s string) bool {
	d := digitsOf(s)
	if len(d) != 16 {
		return false
	}
	province := d[0]*10 + d[1]
	if province < 11 || province > 94 {
		return false
	}
	day := d[6]*10 + d[7]
	month := d[8]*10 + d[9]
	if day > 40 {
		day -= 40
	}
	if !validYMD(2000, month, day) {
		return false
	}
	return !(d[12] == 0 && d[13] == 0 && d[14] == 0 && d[15] == 0)
}
