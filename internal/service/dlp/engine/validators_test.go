package engine

import "testing"

// digitsToString renders a digit slice (values 0..9) as its decimal
// string, used to build deterministic valid identifiers in the same
// way the Rust validator tests do.
func digitsToString(d []int) string {
	b := make([]byte, len(d))
	for i, v := range d {
		b[i] = byte('0' + v)
	}
	return string(b)
}

func TestChinaResidentID(t *testing.T) {
	// 17 body digits with a valid 1990-01-01 DOB; MOD 11-2 check = 5.
	if !chinaResidentID("110101199001010015") {
		t.Error("expected valid china resident id")
	}
	if !chinaResidentID("110101 1990 0101 0015") {
		t.Error("expected valid china id with separators")
	}
	if chinaResidentID("110101199001010010") {
		t.Error("wrong check digit should fail")
	}
	if chinaResidentID("110101199013010015") {
		t.Error("month 13 should fail")
	}
	if chinaResidentID("1101011990010100") {
		t.Error("too short should fail")
	}
}

func TestJapanMyNumber(t *testing.T) {
	base := []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1}
	sum := 0
	for n := 1; n <= 11; n++ {
		p := base[11-n]
		q := n + 1
		if n > 6 {
			q = n - 5
		}
		sum += p * q
	}
	rem := sum % 11
	check := 0
	if rem > 1 {
		check = 11 - rem
	}
	if !japanMyNumber(digitsToString(append(append([]int{}, base...), check))) {
		t.Error("expected valid japan my number")
	}
	bad := append(append([]int{}, base...), (check+1)%10)
	if japanMyNumber(digitsToString(bad)) {
		t.Error("flipped check digit should fail")
	}
	if japanMyNumber("12345678901") {
		t.Error("11 digits should fail")
	}
}

func TestKoreaRRN(t *testing.T) {
	w := []int{2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5}
	d := []int{9, 0, 0, 1, 0, 1, 1, 2, 3, 4, 5, 6, 0}
	sum := 0
	for i, x := range w {
		sum += d[i] * x
	}
	d[12] = (11 - sum%11) % 10
	if !koreaRRN(digitsToString(d)) {
		t.Error("expected valid korea rrn")
	}
	bad := append([]int{}, d...)
	bad[2], bad[3] = 1, 3 // month 13
	if koreaRRN(digitsToString(bad)) {
		t.Error("month 13 should fail")
	}
}

func TestSingaporeNRIC(t *testing.T) {
	if !singaporeNRIC("S1234567D") {
		t.Error("expected valid NRIC")
	}
	if singaporeNRIC("S1234567A") {
		t.Error("wrong check letter should fail")
	}
	if singaporeNRIC("Z1234567D") {
		t.Error("bad prefix should fail")
	}
	if singaporeNRIC("S123456D") {
		t.Error("too short should fail")
	}
}

func TestMalaysiaMyKad(t *testing.T) {
	if !malaysiaMyKad("900101-01-1234") {
		t.Error("expected valid mykad with hyphens")
	}
	if !malaysiaMyKad("900101011234") {
		t.Error("expected valid mykad without hyphens")
	}
	if malaysiaMyKad("901301011234") {
		t.Error("month 13 should fail")
	}
	if malaysiaMyKad("900101701234") {
		t.Error("reserved state 70 should fail")
	}
}

func TestThailandID(t *testing.T) {
	d := []int{1, 1, 0, 1, 7, 0, 0, 1, 2, 3, 4, 5, 0}
	sum := 0
	for i := 0; i < 12; i++ {
		sum += d[i] * (13 - i)
	}
	d[12] = (11 - sum%11) % 10
	if !thailandID(digitsToString(d)) {
		t.Error("expected valid thailand id")
	}
	bad := append([]int{}, d...)
	bad[12] = (d[12] + 1) % 10
	if thailandID(digitsToString(bad)) {
		t.Error("flipped check digit should fail")
	}
}

func TestIndiaAadhaar(t *testing.T) {
	body := []int{2, 3, 4, 1, 2, 3, 4, 5, 6, 7, 8}
	// Brute-force the Verhoeff check digit.
	var full []int
	for c := 0; c < 10; c++ {
		cand := append(append([]int{}, body...), c)
		if verhoeffValid(cand) {
			full = cand
			break
		}
	}
	if full == nil {
		t.Fatal("no valid verhoeff check digit found")
	}
	if !indiaAadhaar(digitsToString(full)) {
		t.Error("expected valid aadhaar")
	}
	if indiaAadhaar("123412345678") {
		t.Error("leading digit < 2 should fail")
	}
}

func TestIndiaPAN(t *testing.T) {
	if !indiaPAN("ABCPK1234L") {
		t.Error("expected valid PAN")
	}
	if indiaPAN("ABCXK1234L") {
		t.Error("X is not a holder type, should fail")
	}
	if indiaPAN("ABCP12345L") {
		t.Error("digit where letter expected should fail")
	}
	if indiaPAN("ABCPK1234") {
		t.Error("too short should fail")
	}
}

func TestUAEEmiratesID(t *testing.T) {
	d := []int{7, 8, 4, 1, 9, 8, 7, 1, 2, 3, 4, 5, 6, 7, 0}
	for c := 0; c < 10; c++ {
		d[14] = c
		if luhnDigits(d) {
			break
		}
	}
	if !uaeEmiratesID(digitsToString(d)) {
		t.Error("expected valid emirates id")
	}
	if uaeEmiratesID("123198712345670") {
		t.Error("wrong prefix should fail")
	}
}

func TestSaudiNationalID(t *testing.T) {
	d := []int{1, 0, 2, 3, 4, 5, 6, 7, 8, 0}
	for c := 0; c < 10; c++ {
		d[9] = c
		if luhnDigits(d) {
			break
		}
	}
	if !saudiNationalID(digitsToString(d)) {
		t.Error("expected valid saudi id")
	}
	if saudiNationalID("3023456780") {
		t.Error("prefix 3 should fail")
	}
}

func TestKuwaitCivilID(t *testing.T) {
	w := []int{2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2}
	// century 2 (1900), DOB 1990-01-01, serial 1234.
	d := []int{2, 9, 0, 0, 1, 0, 1, 1, 2, 3, 4, 0}
	sum := 0
	for i, x := range w {
		sum += d[i] * x
	}
	check := 11 - sum%11
	if check >= 10 {
		t.Fatalf("constructed civil id has check digit %d >= 10", check)
	}
	d[11] = check
	if !kuwaitCivilID(digitsToString(d)) {
		t.Error("expected valid kuwait civil id")
	}
	if kuwaitCivilID("490001012346") {
		t.Error("invalid century digit 4 should fail")
	}
}

func TestVerhoeffValid(t *testing.T) {
	// Classic Verhoeff example: 236 with check digit 3 is valid.
	if !verhoeffValid([]int{2, 3, 6, 3}) {
		t.Error("expected 2363 to be Verhoeff-valid")
	}
	if verhoeffValid([]int{2, 3, 6, 4}) {
		t.Error("expected 2364 to be Verhoeff-invalid")
	}
}
