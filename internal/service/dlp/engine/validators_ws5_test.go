package engine

import (
	"fmt"
	"strings"
	"testing"
)

// These tests are the Go twins of the per-jurisdiction Rust detector
// tests in crates/sng-dlp/src/detectors/. They confirm the Go
// validators decide identically: canonical published numbers pass, and
// a single-digit corruption of a valid number is rejected.

// luhnCheckDigit returns the digit that makes body+digit pass Luhn.
func luhnCheckDigit(body []int) int {
	for c := 0; c <= 9; c++ {
		if luhnDigits(append(append([]int(nil), body...), c)) {
			return c
		}
	}
	return 0
}

func TestUKNINO(t *testing.T) {
	valid := []string{"AB123456C", "AB 12 34 56 C", "ce123456a", "JM456789B"}
	for _, v := range valid {
		if !ukNINO(v) {
			t.Errorf("ukNINO(%q) = false, want true", v)
		}
	}
	invalid := []string{
		"DA123456C",  // illegal first letter D
		"AO123456C",  // illegal second letter O
		"BG123456C",  // disallowed prefix
		"NK123456C",  // disallowed prefix
		"AB123456E",  // suffix outside A-D
		"AB12345C",   // too short
		"A1123456C",  // non-letter prefix
		"ABCD3456C",  // letters where digits expected
		"AB12 34 56", // missing suffix
	}
	for _, v := range invalid {
		if ukNINO(v) {
			t.Errorf("ukNINO(%q) = true, want false", v)
		}
	}
}

func TestUKNHS(t *testing.T) {
	// 9434765919 is a widely published valid NHS test number.
	if !ukNHS("943 476 5919") {
		t.Error("ukNHS(9434765919) should be valid")
	}
	count := 0
	for seed := 0; seed < 400 && count < 60; seed++ {
		body := make([]int, 9)
		for i := range body {
			body[i] = (seed*7 + i*3) % 10
		}
		sum := 0
		for i := 0; i < 9; i++ {
			sum += body[i] * (10 - i)
		}
		check := (11 - sum%11) % 11
		if check == 10 {
			continue // unissued
		}
		num := digitsToString(append(body, check))
		if !ukNHS(num) {
			t.Fatalf("ukNHS(%q) should be valid", num)
		}
		bad := digitsToString(append(append([]int(nil), body...), (check+1)%10))
		if (check+1)%10 != check && ukNHS(bad) {
			t.Fatalf("ukNHS(%q) should be invalid (wrong check)", bad)
		}
		count++
	}
	if count < 50 {
		t.Fatalf("only generated %d NHS vectors", count)
	}
	if ukNHS("12345") || ukNHS("ABCDEFGHIJ") {
		t.Error("malformed NHS inputs must be rejected")
	}
}

func TestCanadaSIN(t *testing.T) {
	count := 0
	for seed := 1; seed < 500 && count < 60; seed++ {
		body := make([]int, 7)
		for i := range body {
			body[i] = (seed*3 + i*7) % 10
		}
		lead := (seed % 9) + 1               // non-zero leading digit
		full := append([]int{lead}, body...) // 8 digits
		check := luhnCheckDigit(full)        // 9th digit
		num := digitsToString(append(full, check))
		if !canadaSIN(num) {
			t.Fatalf("canadaSIN(%q) should be valid", num)
		}
		bad := digitsToString(append(append([]int(nil), full...), (check+1)%10))
		if (check+1)%10 != check && canadaSIN(bad) {
			t.Fatalf("canadaSIN(%q) should be invalid", bad)
		}
		count++
	}
	if count < 50 {
		t.Fatalf("only generated %d SIN vectors", count)
	}
	if canadaSIN("046454286") { // leading zero is unassigned
		t.Error("canadaSIN must reject leading-zero numbers")
	}
}

func TestAustraliaTFN(t *testing.T) {
	count := 0
	for seed := 0; seed < 600 && count < 60; seed++ {
		body := make([]int, 8)
		for i := range body {
			body[i] = (seed*5 + i*2) % 10
		}
		w := []int{1, 4, 3, 7, 5, 8, 6, 9}
		s := 0
		for i := 0; i < 8; i++ {
			s += body[i] * w[i]
		}
		// 9th weight is 10 ≡ -1 (mod 11): need d9 ≡ s (mod 11).
		d9 := s % 11
		if d9 == 10 {
			continue
		}
		num := digitsToString(append(append([]int(nil), body...), d9))
		if !australiaTFN(num) {
			t.Fatalf("australiaTFN(%q) should be valid", num)
		}
		bad := digitsToString(append(append([]int(nil), body...), (d9+1)%10))
		if (d9+1)%10 != d9 && australiaTFN(bad) {
			t.Fatalf("australiaTFN(%q) should be invalid", bad)
		}
		count++
	}
	if count < 50 {
		t.Fatalf("only generated %d TFN vectors", count)
	}
}

func TestAustraliaMedicare(t *testing.T) {
	count := 0
	for seed := 0; seed < 600 && count < 60; seed++ {
		body := make([]int, 8)
		body[0] = (seed % 5) + 2 // first digit 2..6
		for i := 1; i < 8; i++ {
			body[i] = (seed*3 + i*7) % 10
		}
		w := []int{1, 3, 7, 9, 1, 3, 7, 9}
		s := 0
		for i := 0; i < 8; i++ {
			s += body[i] * w[i]
		}
		check := s % 10
		issue := seed % 10
		num := digitsToString(append(append(body, check), issue))
		if !australiaMedicare(num) {
			t.Fatalf("australiaMedicare(%q) should be valid", num)
		}
		bad := digitsToString(append(append(append([]int(nil), body...), (check+1)%10), issue))
		if (check+1)%10 != check && australiaMedicare(bad) {
			t.Fatalf("australiaMedicare(%q) should be invalid", bad)
		}
		count++
	}
	if count < 50 {
		t.Fatalf("only generated %d Medicare vectors", count)
	}
	if australiaMedicare("7234567890") { // first digit out of 2..6
		t.Error("medicare first digit must be 2..6")
	}
}

func TestGermanyPersonalausweis(t *testing.T) {
	alphabet := []rune("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	count := 0
	for seed := 0; seed < 600 && count < 60; seed++ {
		body := make([]rune, 9)
		for i := range body {
			body[i] = alphabet[(seed*7+i*5)%len(alphabet)]
		}
		w := []int{7, 3, 1}
		sum := 0
		for i := 0; i < 9; i++ {
			v, _ := alnumValue(body[i])
			sum += v * w[i%3]
		}
		check := sum % 10
		num := string(body) + fmt.Sprintf("%d", check)
		if !germanyPersonalausweis(num) {
			t.Fatalf("germanyPersonalausweis(%q) should be valid", num)
		}
		bad := string(body) + fmt.Sprintf("%d", (check+1)%10)
		if (check+1)%10 != check && germanyPersonalausweis(bad) {
			t.Fatalf("germanyPersonalausweis(%q) should be invalid", bad)
		}
		count++
	}
	if count < 50 {
		t.Fatalf("only generated %d Personalausweis vectors", count)
	}
}

func TestFranceINSEE(t *testing.T) {
	count := 0
	for seed := 0; seed < 600 && count < 60; seed++ {
		sex := (seed % 2) + 1
		yy := seed % 100
		mm := (seed % 12) + 1
		dept := (seed % 95) + 1
		commune := seed % 1000
		order := (seed % 999) + 1
		body := fmt.Sprintf("%d%02d%02d%02d%03d%03d", sex, yy, mm, dept, commune, order)
		var n int64
		fmt.Sscanf(body, "%d", &n)
		key := 97 - (n % 97)
		num := fmt.Sprintf("%s%02d", body, key)
		if !franceINSEE(num) {
			t.Fatalf("franceINSEE(%q) should be valid", num)
		}
		badKey := (key % 97) + 1
		bad := fmt.Sprintf("%s%02d", body, badKey)
		if badKey != key && franceINSEE(bad) {
			t.Fatalf("franceINSEE(%q) should be invalid", bad)
		}
		count++
	}
	if count < 50 {
		t.Fatalf("only generated %d INSEE vectors", count)
	}
	// Corsica 2A folds the department code to 0 with a -1,000,000
	// numeric offset before the mod-97 key. Body =
	// sex1 yy80 mm02 dept"2A" commune123 order456.
	corsicaBody := "180022A123456"
	foldedStr := strings.ReplaceAll(corsicaBody, "A", "0")
	var folded int64
	fmt.Sscanf(foldedStr, "%d", &folded)
	folded -= 1_000_000
	corsicaKey := 97 - (folded % 97)
	corsica := fmt.Sprintf("%s%02d", corsicaBody, corsicaKey)
	if !franceINSEE(corsica) {
		t.Errorf("franceINSEE Corsica %q should be valid", corsica)
	}
}

func TestBrazilCPF(t *testing.T) {
	count := 0
	for seed := 0; seed < 600 && count < 60; seed++ {
		body := make([]int, 9)
		for i := range body {
			body[i] = (seed*3 + i*7) % 10
		}
		if allSameDigits(body) {
			continue
		}
		c1 := brMod11(body, 10)
		full := append(append([]int(nil), body...), c1)
		c2 := brMod11(full, 11)
		num := digitsToString(append(full, c2))
		if !brazilCPF(num) {
			t.Fatalf("brazilCPF(%q) should be valid", num)
		}
		bad := digitsToString(append(append([]int(nil), full...), (c2+1)%10))
		if (c2+1)%10 != c2 && brazilCPF(bad) {
			t.Fatalf("brazilCPF(%q) should be invalid", bad)
		}
		count++
	}
	if count < 50 {
		t.Fatalf("only generated %d CPF vectors", count)
	}
	if brazilCPF("11111111111") {
		t.Error("repdigit CPF must be rejected")
	}
}

func TestBrazilCNPJ(t *testing.T) {
	w1 := []int{5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2}
	w2 := []int{6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2}
	count := 0
	for seed := 0; seed < 600 && count < 60; seed++ {
		body := make([]int, 12)
		for i := range body {
			body[i] = (seed*3 + i*5) % 10
		}
		if allSameDigits(body) {
			continue
		}
		c1 := cnpjCheck(body, w1)
		full := append(append([]int(nil), body...), c1)
		c2 := cnpjCheck(full, w2)
		num := digitsToString(append(full, c2))
		if !brazilCNPJ(num) {
			t.Fatalf("brazilCNPJ(%q) should be valid", num)
		}
		bad := digitsToString(append(append([]int(nil), full...), (c2+1)%10))
		if (c2+1)%10 != c2 && brazilCNPJ(bad) {
			t.Fatalf("brazilCNPJ(%q) should be invalid", bad)
		}
		count++
	}
	if count < 50 {
		t.Fatalf("only generated %d CNPJ vectors", count)
	}
}

func TestEUIBAN(t *testing.T) {
	// Canonical published IBANs.
	valid := []string{
		"GB82WEST12345698765432",
		"DE89370400440532013000",
		"FR1420041010050500013M02606",
		"NL91ABNA0417164300",
		"BE68539007547034",
	}
	for _, v := range valid {
		if !euIBAN(v) {
			t.Errorf("euIBAN(%q) = false, want true", v)
		}
	}
	invalid := []string{
		"GB82WEST12345698765431", // bad check
		"DE89370400440532013001", // bad check
		"XX00",                   // too short
		"1234567890123456",       // no country letters
	}
	for _, v := range invalid {
		if euIBAN(v) {
			t.Errorf("euIBAN(%q) = true, want false", v)
		}
	}
}

func TestEUVAT(t *testing.T) {
	valid := []string{
		"ATU13585627",    // Austria
		"BE0776091951",   // Belgium
		"DE136695976",    // Germany
		"DK13585628",     // Denmark (sum%11==0)
		"FR40303265045",  // France
		"IT00743110157",  // Italy
		"PL5260001246",   // Poland
		"NL010000446B01", // Netherlands
	}
	for _, v := range valid {
		if !euVAT(v) {
			t.Errorf("euVAT(%q) = false, want true", v)
		}
	}
	invalid := []string{
		"ATU13585628",  // bad Austrian check
		"DE136695977",  // bad German check
		"BE0776091952", // bad Belgian check
		"ZZ123456789",  // unknown country
		"PL5260001247", // bad Polish check
	}
	for _, v := range invalid {
		if euVAT(v) {
			t.Errorf("euVAT(%q) = true, want false", v)
		}
	}
}

func TestPhilippinesUMID(t *testing.T) {
	count := 0
	for seed := 0; seed < 200 && count < 60; seed++ {
		d := make([]int, 12)
		d[0] = (seed % 9) + 1
		for i := 1; i < 12; i++ {
			d[i] = (seed*3 + i*7) % 10
		}
		if allSameDigits(d) {
			continue
		}
		num := digitsToString(d)
		if !philippinesUMID(num) {
			t.Fatalf("philippinesUMID(%q) should be valid", num)
		}
		count++
	}
	if count < 50 {
		t.Fatalf("only generated %d UMID vectors", count)
	}
	if philippinesUMID("012345678901") || philippinesUMID("111111111111") {
		t.Error("UMID must reject leading-zero and repdigit numbers")
	}
}

func TestIndonesiaNIK(t *testing.T) {
	count := 0
	for seed := 0; seed < 600 && count < 60; seed++ {
		province := (seed % 84) + 11 // 11..94
		regency := seed % 100
		district := seed % 100
		day := (seed % 28) + 1
		month := (seed % 12) + 1
		yy := seed % 100
		female := seed%2 == 0
		d := day
		if female {
			d += 40
		}
		serial := (seed % 9998) + 1
		num := fmt.Sprintf("%02d%02d%02d%02d%02d%02d%04d", province, regency, district, d, month, yy, serial)
		if !indonesiaNIK(num) {
			t.Fatalf("indonesiaNIK(%q) should be valid (day=%d month=%d)", num, day, month)
		}
		count++
	}
	if count < 50 {
		t.Fatalf("only generated %d NIK vectors", count)
	}
	bad := []string{
		"1011010101010001", // province 10 < 11
		"9511010101010001", // province 95 > 94
		"3201013413010001", // day 34 (not female-shifted) invalid
		"320101010101000",  // 15 digits
	}
	for _, v := range bad {
		if indonesiaNIK(v) {
			t.Errorf("indonesiaNIK(%q) = true, want false", v)
		}
	}
}
