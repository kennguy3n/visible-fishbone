package engine

// Workstream-10c jurisdiction validators.
//
// Each function here is the byte-identical Go twin of a validator in
// crates/sng-dlp/src/detectors/, extending the national-ID coverage in
// validators.go / validators_ws5.go to Ireland, Switzerland, Israel,
// Romania and Mexico. The endpoint (Rust) and the control-plane SWG
// (Go) must decide identically, so the algorithms below mirror the Rust
// detectors exactly — same weights, same separators stripped, same
// accept/reject edges.

// ppsnCheckAlphabet selects the Ireland PPSN check letter: index
// Σ mod 23, where index 0 maps to W. Mirrors `CHECK_ALPHABET`.
const ppsnCheckAlphabet = "WABCDEFGHIJKLMNOPQRSTUV"

// irelandPPSN validates an Ireland PPS Number: seven digits, a check
// letter, and an optional second letter (A..=I or W). The check letter
// is the weighted mod-23 sum of the seven digits (weights 8..=2) plus,
// for the nine-character form, nine times the second letter's value
// (A=1.., W=0). Mirrors `ireland_ppsn`.
func irelandPPSN(s string) bool {
	c := make([]rune, 0, len(s))
	for _, r := range s {
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' || r == '-' {
			continue
		}
		c = append(c, r)
	}
	if len(c) != 8 && len(c) != 9 {
		return false
	}
	sum := 0
	for i := 0; i < 7; i++ {
		if c[i] < '0' || c[i] > '9' {
			return false
		}
		sum += int(c[i]-'0') * (8 - i)
	}
	check := c[7]
	if check >= 'a' && check <= 'z' {
		check -= 'a' - 'A'
	}
	if check < 'A' || check > 'Z' {
		return false
	}
	if len(c) == 9 {
		extra := c[8]
		if extra >= 'a' && extra <= 'z' {
			extra -= 'a' - 'A'
		}
		switch {
		case extra == 'W':
			// value 0, no contribution
		case extra >= 'A' && extra <= 'I':
			sum += int(extra-'A'+1) * 9
		default:
			return false
		}
	}
	return ppsnCheckAlphabet[sum%23] == byte(check)
}

// switzerlandAHV validates a Switzerland AHV/AVS number: thirteen
// digits beginning 756, the last an EAN-13 check digit over the first
// twelve (weights alternate 1,3 from the leftmost digit). Mirrors
// `switzerland_ahv`.
func switzerlandAHV(s string) bool {
	d := digitsOf(s)
	if len(d) != 13 {
		return false
	}
	if d[0] != 7 || d[1] != 5 || d[2] != 6 {
		return false
	}
	sum := 0
	for i := 0; i < 12; i++ {
		weight := 1
		if i%2 == 1 {
			weight = 3
		}
		sum += d[i] * weight
	}
	check := (10 - sum%10) % 10
	return d[12] == check
}

// israelID validates an Israel Teudat Zehut: nine digits with a
// Luhn-style check where odd positions weight 1 and even positions
// weight 2 (one-based, from the left), each two-digit product folded by
// subtracting nine, and the total a multiple of ten. Mirrors
// `israel_id`.
func israelID(s string) bool {
	d := digitsOf(s)
	if len(d) != 9 {
		return false
	}
	sum := 0
	for i, digit := range d {
		v := digit
		if i%2 == 1 {
			v *= 2
		}
		if v > 9 {
			v -= 9
		}
		sum += v
	}
	return sum%10 == 0
}

// romaniaCNPWeights are the weighted mod-11 CNP check weights. Mirrors
// `WEIGHTS`.
var romaniaCNPWeights = [12]int{2, 7, 9, 1, 4, 6, 3, 5, 8, 2, 7, 9}

// romaniaCenturyBase returns the birth-century base year for the CNP
// sex/century digit, or (0,false) when it is not a CNP-issued value.
// Mirrors `century`.
func romaniaCenturyBase(sex int) (int, bool) {
	switch sex {
	case 1, 2:
		return 1900, true
	case 3, 4:
		return 1800, true
	case 5, 6:
		return 2000, true
	case 7, 8:
		return 2000, true
	default:
		return 0, false
	}
}

// romaniaCNP validates a Romania CNP: thirteen digits with a valid
// sex/century digit, a real date of birth, a county code in 01..=52 or
// 70, a non-zero serial and the weighted mod-11 check digit. Mirrors
// `romania_cnp`.
func romaniaCNP(s string) bool {
	d := digitsOf(s)
	if len(d) != 13 {
		return false
	}
	base, ok := romaniaCenturyBase(d[0])
	if !ok {
		return false
	}
	yy := d[1]*10 + d[2]
	mm := d[3]*10 + d[4]
	dd := d[5]*10 + d[6]
	if !validYMD(base+yy, mm, dd) {
		return false
	}
	county := d[7]*10 + d[8]
	if (county < 1 || county > 52) && county != 70 {
		return false
	}
	serial := d[9]*100 + d[10]*10 + d[11]
	if serial == 0 {
		return false
	}
	sum := 0
	for i := 0; i < 12; i++ {
		sum += romaniaCNPWeights[i] * d[i]
	}
	check := sum % 11
	if check == 10 {
		check = 1
	}
	return d[12] == check
}

// mexicoStateCodes are the valid two-letter Mexican federal-entity
// codes plus NE (births abroad). Mirrors `STATE_CODES`.
var mexicoStateCodes = map[string]struct{}{
	"AS": {}, "BC": {}, "BS": {}, "CC": {}, "CL": {}, "CM": {}, "CS": {}, "CH": {},
	"DF": {}, "DG": {}, "GT": {}, "GR": {}, "HG": {}, "JC": {}, "MC": {}, "MN": {},
	"MS": {}, "NT": {}, "NL": {}, "OC": {}, "PL": {}, "QT": {}, "QR": {}, "SP": {},
	"SL": {}, "SR": {}, "TC": {}, "TS": {}, "TL": {}, "VZ": {}, "YN": {}, "ZS": {},
	"NE": {},
}

// curpValue maps a CURP character to its value in the RENAPO dictionary
// `0-9 A-N Ñ O-Z` (0..=36), or (0,false) for any character outside it.
// Mirrors `curp_value`.
func curpValue(ch rune) (int, bool) {
	switch {
	case ch >= '0' && ch <= '9':
		return int(ch - '0'), true
	case ch >= 'A' && ch <= 'N':
		return int(ch-'A') + 10, true
	case ch == 'Ñ':
		return 24, true
	case ch >= 'O' && ch <= 'Z':
		return int(ch-'O') + 25, true
	default:
		return 0, false
	}
}

// mexicoCURP validates a Mexico CURP: eighteen characters with a valid
// date of birth, sex letter, federal-entity code and the RENAPO mod-10
// check digit over the first seventeen characters (weights 18..=2).
// Mirrors `mexico_curp`.
func mexicoCURP(s string) bool {
	c := []rune(s)
	if len(c) != 18 {
		return false
	}
	for i := 0; i < 4; i++ {
		if c[i] < 'A' || c[i] > 'Z' {
			return false
		}
	}
	date := [6]int{}
	for i := 0; i < 6; i++ {
		if c[4+i] < '0' || c[4+i] > '9' {
			return false
		}
		date[i] = int(c[4+i] - '0')
	}
	if c[10] != 'H' && c[10] != 'M' {
		return false
	}
	state := string(c[11:13])
	if _, ok := mexicoStateCodes[state]; !ok {
		return false
	}
	for i := 13; i < 16; i++ {
		if c[i] < 'A' || c[i] > 'Z' {
			return false
		}
	}
	homoclaveDigit := c[16] >= '0' && c[16] <= '9'
	if !homoclaveDigit && (c[16] < 'A' || c[16] > 'Z') {
		return false
	}
	if c[17] < '0' || c[17] > '9' {
		return false
	}
	yy := date[0]*10 + date[1]
	mm := date[2]*10 + date[3]
	dd := date[4]*10 + date[5]
	base := 2000
	if homoclaveDigit {
		base = 1900
	}
	if !validYMD(base+yy, mm, dd) {
		return false
	}
	sum := 0
	for i := 0; i < 17; i++ {
		v, ok := curpValue(c[i])
		if !ok {
			return false
		}
		sum += v * (18 - i)
	}
	check := (10 - sum%10) % 10
	return int(c[17]-'0') == check
}
