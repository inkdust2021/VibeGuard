package config

import "testing"

func TestSanitizePatternValue_移除不可见字符(t *testing.T) {
	in := "\x1FSamuel Porter\u200B"
	got := SanitizePatternValue(in)
	want := "Samuel Porter"
	if got != want {
		t.Fatalf("SanitizePatternValue()=%q, want %q", got, want)
	}
}

func TestSanitizeCategory_仅保留安全字符并转大写(t *testing.T) {
	in := " name-foo bar \x1f "
	got := SanitizeCategory(in)
	want := "NAME_FOO_BAR"
	if got != want {
		t.Fatalf("SanitizeCategory()=%q, want %q", got, want)
	}
}
