package engine

import "unicode"

// EU VAT identification number validator, the Go twin of
// crates/sng-dlp/src/detectors/europe.rs::eu_vat. Member states whose
// check-digit algorithm is published and unambiguous
// (AT, BE, DE, DK, FI, FR, IT, LU, PL, PT, SE) are fully verified;
// the remainder are validated structurally (country code, length,
// charset). The EL prefix (Greece's VAT code) maps to its algorithm.

func euVAT(s string) bool {
	c := make([]rune, 0, len(s))
	for _, r := range s {
		if unicode.IsSpace(r) {
			continue
		}
		if r >= 'a' && r <= 'z' {
			r -= 'a' - 'A'
		}
		c = append(c, r)
	}
	if len(c) < 4 {
		return false
	}
	country := string(c[0:2])
	rest := c[2:]
	switch country {
	case "AT":
		return vatAustria(rest)
	case "BE":
		return vatBelgium(rest)
	case "DE":
		return vatGermany(rest)
	case "DK":
		return vatDenmark(rest)
	case "EL":
		return vatGreece(rest)
	case "FI":
		return vatFinland(rest)
	case "FR":
		return vatFrance(rest)
	case "IT":
		return vatItaly(rest)
	case "LU":
		return vatLuxembourg(rest)
	case "PL":
		return vatPoland(rest)
	case "PT":
		return vatPortugal(rest)
	case "SE":
		return vatSweden(rest)
	case "BG":
		return vatStructural(rest, []int{9, 10}, false)
	case "CY":
		return vatStructural(rest, []int{9}, true)
	case "CZ":
		return vatStructural(rest, []int{8, 9, 10}, false)
	case "EE":
		return vatStructural(rest, []int{9}, false)
	case "ES":
		return vatStructural(rest, []int{9}, true)
	case "HR":
		return vatStructural(rest, []int{11}, false)
	case "HU":
		return vatStructural(rest, []int{8}, false)
	case "IE":
		return vatStructural(rest, []int{8, 9}, true)
	case "LT":
		return vatStructural(rest, []int{9, 12}, false)
	case "LV":
		return vatStructural(rest, []int{11}, false)
	case "MT":
		return vatStructural(rest, []int{8}, false)
	case "NL":
		return vatNetherlands(rest)
	case "RO":
		return vatStructuralRange(rest, 2, 10, false)
	case "SI":
		return vatStructural(rest, []int{8}, false)
	case "SK":
		return vatStructural(rest, []int{10}, false)
	default:
		return false
	}
}

func vatStructural(rest []rune, lengths []int, alpha bool) bool {
	ok := false
	for _, l := range lengths {
		if len(rest) == l {
			ok = true
			break
		}
	}
	if !ok {
		return false
	}
	return vatCharset(rest, alpha)
}

func vatStructuralRange(rest []rune, min, max int, alpha bool) bool {
	if len(rest) < min || len(rest) > max {
		return false
	}
	return vatCharset(rest, alpha)
}

func vatCharset(rest []rune, alpha bool) bool {
	for _, r := range rest {
		isDigit := r >= '0' && r <= '9'
		isAlnum := isDigit || (r >= 'A' && r <= 'Z')
		if !(isDigit || (alpha && isAlnum)) {
			return false
		}
	}
	return true
}

// vatDigits converts rest to a digit slice, or (nil, false) if any
// rune is not a decimal digit.
func vatDigits(rest []rune) ([]int, bool) {
	d := make([]int, len(rest))
	for i, r := range rest {
		if r < '0' || r > '9' {
			return nil, false
		}
		d[i] = int(r - '0')
	}
	return d, true
}

func vatAustria(rest []rune) bool {
	if len(rest) != 9 || rest[0] != 'U' {
		return false
	}
	d, ok := vatDigits(rest[1:])
	if !ok {
		return false
	}
	w := [7]int{1, 2, 1, 2, 1, 2, 1}
	sum := 0
	for i := 0; i < 7; i++ {
		p := d[i] * w[i]
		sum += p/10 + p%10
	}
	check := ((96-sum)%10 + 10) % 10
	return check == d[7]
}

func vatBelgium(rest []rune) bool {
	d, ok := vatDigits(rest)
	if !ok || len(d) != 10 {
		return false
	}
	first8 := 0
	for i := 0; i < 8; i++ {
		first8 = first8*10 + d[i]
	}
	last2 := d[8]*10 + d[9]
	return 97-first8%97 == last2
}

func vatGermany(rest []rune) bool {
	d, ok := vatDigits(rest)
	if !ok || len(d) != 9 {
		return false
	}
	product := 10
	for i := 0; i < 8; i++ {
		sum := (d[i] + product) % 10
		if sum == 0 {
			sum = 10
		}
		product = (sum * 2) % 11
	}
	check := (11 - product) % 10
	return check == d[8]
}

func vatDenmark(rest []rune) bool {
	d, ok := vatDigits(rest)
	if !ok || len(d) != 8 {
		return false
	}
	w := [8]int{2, 7, 6, 5, 4, 3, 2, 1}
	sum := 0
	for i, x := range d {
		sum += x * w[i]
	}
	return sum%11 == 0
}

func vatGreece(rest []rune) bool {
	d, ok := vatDigits(rest)
	if !ok || len(d) != 9 {
		return false
	}
	sum := 0
	w := 256
	for i := 0; i < 8; i++ {
		sum += d[i] * w
		w /= 2
	}
	check := (sum % 11) % 10
	return check == d[8]
}

func vatFinland(rest []rune) bool {
	d, ok := vatDigits(rest)
	if !ok || len(d) != 8 {
		return false
	}
	w := [7]int{7, 9, 10, 5, 8, 4, 2}
	sum := 0
	for i := 0; i < 7; i++ {
		sum += d[i] * w[i]
	}
	rem := sum % 11
	if rem == 1 {
		return false
	}
	check := 0
	if rem != 0 {
		check = 11 - rem
	}
	return check == d[7]
}

func vatFrance(rest []rune) bool {
	if len(rest) != 11 {
		return false
	}
	siren, ok := vatDigits(rest[2:])
	if !ok {
		return false
	}
	if !luhnDigits(siren) {
		return false
	}
	if rest[0] >= '0' && rest[0] <= '9' && rest[1] >= '0' && rest[1] <= '9' {
		key := int(rest[0]-'0')*10 + int(rest[1]-'0')
		sirenNum := 0
		for _, x := range siren {
			sirenNum = sirenNum*10 + x
		}
		expected := (12 + 3*(sirenNum%97)) % 97
		return key == expected
	}
	isAlnum := func(r rune) bool {
		return (r >= '0' && r <= '9') || (r >= 'A' && r <= 'Z')
	}
	return isAlnum(rest[0]) && isAlnum(rest[1])
}

func vatItaly(rest []rune) bool {
	d, ok := vatDigits(rest)
	return ok && len(d) == 11 && luhnDigits(d)
}

func vatLuxembourg(rest []rune) bool {
	d, ok := vatDigits(rest)
	if !ok || len(d) != 8 {
		return false
	}
	first6 := 0
	for i := 0; i < 6; i++ {
		first6 = first6*10 + d[i]
	}
	last2 := d[6]*10 + d[7]
	return first6%89 == last2
}

func vatPoland(rest []rune) bool {
	d, ok := vatDigits(rest)
	if !ok || len(d) != 10 {
		return false
	}
	w := [9]int{6, 5, 7, 2, 3, 4, 5, 6, 7}
	sum := 0
	for i := 0; i < 9; i++ {
		sum += d[i] * w[i]
	}
	check := sum % 11
	return check != 10 && check == d[9]
}

func vatPortugal(rest []rune) bool {
	d, ok := vatDigits(rest)
	if !ok || len(d) != 9 {
		return false
	}
	w := [8]int{9, 8, 7, 6, 5, 4, 3, 2}
	sum := 0
	for i := 0; i < 8; i++ {
		sum += d[i] * w[i]
	}
	rem := sum % 11
	check := 0
	if rem > 1 {
		check = 11 - rem
	}
	return check == d[8]
}

func vatSweden(rest []rune) bool {
	d, ok := vatDigits(rest)
	if !ok || len(d) != 12 {
		return false
	}
	if d[10] != 0 || d[11] != 1 {
		return false
	}
	return luhnDigits(d[:10])
}

func vatNetherlands(rest []rune) bool {
	if len(rest) != 12 || rest[9] != 'B' {
		return false
	}
	for i := 0; i < 9; i++ {
		if rest[i] < '0' || rest[i] > '9' {
			return false
		}
	}
	for i := 10; i < 12; i++ {
		if rest[i] < '0' || rest[i] > '9' {
			return false
		}
	}
	return true
}
