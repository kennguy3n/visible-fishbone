package engine

import (
	"fmt"
	"testing"
)

// These tests are the Go twins of the per-jurisdiction Rust detector
// tests in crates/sng-dlp/src/detectors/. They confirm the Go
// validators decide identically: canonical published numbers pass, and
// a single-character corruption of a valid number is rejected.

func TestIrelandPPSN(t *testing.T) {
	make8 := func(body [7]int) string {
		sum := 0
		for i := 0; i < 7; i++ {
			sum += body[i] * (8 - i)
		}
		letter := ppsnCheckAlphabet[sum%23]
		s := ""
		for _, d := range body {
			s += string(rune('0' + d))
		}
		return s + string(rune(letter))
	}
	count := 0
	for seed := 0; seed < 200 && count < 40; seed++ {
		var body [7]int
		v := seed*2654435 + 7
		for i := range body {
			body[i] = v % 10
			v /= 10
			v += seed + 1
		}
		good := make8(body)
		if !irelandPPSN(good) {
			t.Errorf("irelandPPSN(%q) = false, want true", good)
		}
		// Corrupt the check letter to the next in the alphabet.
		last := good[7]
		pos := 0
		for i := 0; i < len(ppsnCheckAlphabet); i++ {
			if ppsnCheckAlphabet[i] == last {
				pos = i
				break
			}
		}
		bad := good[:7] + string(rune(ppsnCheckAlphabet[(pos+1)%23]))
		if irelandPPSN(bad) {
			t.Errorf("irelandPPSN(%q) = true, want false", bad)
		}
		count++
	}
	if count < 40 {
		t.Fatalf("only %d vectors exercised", count)
	}
	// Nine-character form: trailing W contributes zero.
	nine := make8([7]int{1, 2, 3, 4, 5, 6, 7}) + "W"
	if !irelandPPSN(nine) {
		t.Errorf("irelandPPSN(%q) = false, want true", nine)
	}
	for _, bad := range []string{"123456T", "12345678", "1234567TZ", "A234567T"} {
		if irelandPPSN(bad) {
			t.Errorf("irelandPPSN(%q) = true, want false", bad)
		}
	}
}

func TestSwitzerlandAHV(t *testing.T) {
	// 756.1234.5678.97 is the canonical worked example.
	if !switzerlandAHV("7561234567897") || !switzerlandAHV("756.1234.5678.97") {
		t.Error("switzerlandAHV(7561234567897) should be valid")
	}
	count := 0
	for seed := 0; seed < 200 && count < 40; seed++ {
		d := []int{7, 5, 6}
		v := seed*40503661 + 3
		for i := 0; i < 9; i++ {
			d = append(d, v%10)
			v /= 10
			v += seed + 2
		}
		sum := 0
		for i := 0; i < 12; i++ {
			w := 1
			if i%2 == 1 {
				w = 3
			}
			sum += d[i] * w
		}
		check := (10 - sum%10) % 10
		good := ""
		for _, x := range append(d, check) {
			good += string(rune('0' + x))
		}
		if !switzerlandAHV(good) {
			t.Errorf("switzerlandAHV(%q) = false, want true", good)
		}
		bad := good[:12] + string(rune('0'+(check+1)%10))
		if switzerlandAHV(bad) {
			t.Errorf("switzerlandAHV(%q) = true, want false", bad)
		}
		count++
	}
	for _, bad := range []string{"7561234567890", "123456789012", "7551234567897"} {
		if switzerlandAHV(bad) {
			t.Errorf("switzerlandAHV(%q) = true, want false", bad)
		}
	}
}

func TestIsraelID(t *testing.T) {
	// 123456782 is a widely cited valid Teudat Zehut.
	if !israelID("123456782") {
		t.Error("israelID(123456782) should be valid")
	}
	checkDigit := func(body [8]int) int {
		sum := 0
		for i, digit := range body {
			v := digit
			if i%2 == 1 {
				v *= 2
			}
			if v > 9 {
				v -= 9
			}
			sum += v
		}
		return (10 - sum%10) % 10
	}
	count := 0
	for seed := 0; seed < 200 && count < 40; seed++ {
		var body [8]int
		v := seed*2246822 + 5
		for i := range body {
			body[i] = v % 10
			v /= 10
			v += seed + 3
		}
		check := checkDigit(body)
		good := ""
		for _, d := range body {
			good += string(rune('0' + d))
		}
		good += string(rune('0' + check))
		if !israelID(good) {
			t.Errorf("israelID(%q) = false, want true", good)
		}
		bad := good[:8] + string(rune('0'+(check+1)%10))
		if israelID(bad) {
			t.Errorf("israelID(%q) = true, want false", bad)
		}
		count++
	}
	for _, bad := range []string{"12345678", "1234567890", "123456789"} {
		if israelID(bad) {
			t.Errorf("israelID(%q) = true, want false", bad)
		}
	}
}

func TestRomaniaCNP(t *testing.T) {
	makeCNP := func(sex, yy, mm, dd, county, serial int) string {
		d := []int{
			sex, yy / 10, yy % 10, mm / 10, mm % 10, dd / 10, dd % 10,
			county / 10, county % 10, serial / 100 % 10, serial / 10 % 10, serial % 10,
		}
		sum := 0
		for i := 0; i < 12; i++ {
			sum += romaniaCNPWeights[i] * d[i]
		}
		check := sum % 11
		if check == 10 {
			check = 1
		}
		d = append(d, check)
		s := ""
		for _, x := range d {
			s += string(rune('0' + x))
		}
		return s
	}
	count := 0
	for seed := 0; seed < 200 && count < 40; seed++ {
		good := makeCNP(seed%8+1, seed*7%100, seed%12+1, seed%28+1, seed%52+1, seed%999+1)
		if !romaniaCNP(good) {
			t.Errorf("romaniaCNP(%q) = false, want true", good)
		}
		last := int(good[12] - '0')
		bad := good[:12] + string(rune('0'+(last+1)%10))
		if romaniaCNP(bad) {
			t.Errorf("romaniaCNP(%q) = true, want false", bad)
		}
		count++
	}
	good := makeCNP(1, 80, 6, 15, 40, 123)
	bads := []string{
		good[:3] + "99" + good[5:], // impossible month
		good[:7] + "00" + good[9:], // county 00
		"0" + good[1:],             // sex digit 0
		"9" + good[1:],             // sex digit 9
		good[:12],                  // 12 digits
	}
	for _, bad := range bads {
		if romaniaCNP(bad) {
			t.Errorf("romaniaCNP(%q) = true, want false", bad)
		}
	}
}

func TestMexicoCURP(t *testing.T) {
	checkDigit := func(head string) int {
		sum := 0
		for i, ch := range head {
			v, ok := curpValue(ch)
			if !ok {
				t.Fatalf("non-dictionary char %q in head %q", ch, head)
			}
			sum += v * (18 - i)
		}
		return (10 - sum%10) % 10
	}
	names := []string{"PEPP", "MARL", "GOHM", "LOAN", "RAQU"}
	cons := []string{"RRL", "NXX", "BCD", "FGH", "JKL"}
	states := []string{"AS", "BC", "DF", "JC", "NL", "VZ"}
	count := 0
	for seed := 0; seed < 200 && count < 40; seed++ {
		sex := "H"
		if seed%2 == 1 {
			sex = "M"
		}
		head := fmt.Sprintf("%s%02d%02d%02d%s%s%s%d",
			names[seed%len(names)], seed%100, seed%12+1, seed%28+1,
			sex, states[seed%len(states)], cons[seed%len(cons)], seed%10)
		good := head + fmt.Sprintf("%d", checkDigit(head))
		if !mexicoCURP(good) {
			t.Errorf("mexicoCURP(%q) = false, want true", good)
		}
		last := int(good[17] - '0')
		bad := head + fmt.Sprintf("%d", (last+1)%10)
		if mexicoCURP(bad) {
			t.Errorf("mexicoCURP(%q) = true, want false", bad)
		}
		count++
	}
	good := "PEPP900101HDFRRL0" + fmt.Sprintf("%d", checkDigit("PEPP900101HDFRRL0"))
	bads := []string{
		"PEPP9099" + good[8:],        // impossible month
		good[:11] + "ZZ" + good[13:], // unknown state
		good[:10] + "X" + good[11:],  // wrong sex letter
		good[:17],                    // 17 chars
	}
	for _, bad := range bads {
		if mexicoCURP(bad) {
			t.Errorf("mexicoCURP(%q) = true, want false", bad)
		}
	}
}
