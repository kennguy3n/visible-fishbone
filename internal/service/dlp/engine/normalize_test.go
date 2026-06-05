package engine

import "testing"

func TestNormalizeNFC_Composes(t *testing.T) {
	// Decomposed "e" + combining acute accent -> composed "é".
	if got := normalizeNFC("e\u0301"); got != "\u00e9" {
		t.Errorf("normalizeNFC did not compose: %q", got)
	}
	// ASCII is unchanged so offsets/snippets are preserved.
	if got := normalizeNFC("plain ascii 12345"); got != "plain ascii 12345" {
		t.Errorf("NFC altered ASCII: %q", got)
	}
}

func TestSimhashTokens_Whitespace(t *testing.T) {
	got := simhashTokens("hello world foo")
	want := []string{"hello", "world", "foo"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("token %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestSimhashTokens_CJKBigrams(t *testing.T) {
	// 5 CJK chars -> 4 overlapping bigrams.
	got := simhashTokens("身份证号码")
	want := []string{"身份", "份证", "证号", "号码"}
	if len(got) != len(want) {
		t.Fatalf("got %v (len %d), want %v", got, len(got), want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("bigram %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestSimhashTokens_ThaiTrigrams(t *testing.T) {
	// 6 Thai chars -> 4 overlapping trigrams.
	got := simhashTokens("กขคงจฉ")
	if len(got) != 4 {
		t.Fatalf("expected 4 trigrams, got %d: %v", len(got), got)
	}
	if len([]rune(got[0])) != 3 {
		t.Errorf("first token %q is not a trigram", got[0])
	}
}

func TestSimHash_CJKDiscriminates(t *testing.T) {
	// Different CJK content yields different hashes; identical content
	// yields identical hashes (bigram tokenization is deterministic).
	a := SimHash([]byte("身份证号码一二三"))
	b := SimHash([]byte("身份证号码一二三"))
	c := SimHash([]byte("完全不同的中文内容"))
	if a != b {
		t.Error("identical CJK content must hash identically")
	}
	if a == c {
		t.Error("distinct CJK content should not collide")
	}
}
