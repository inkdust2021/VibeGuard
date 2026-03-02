package presidio

import "testing"

func TestNewRecognizers_EmptyUsesSafeDefaults(t *testing.T) {
	t.Parallel()

	recs, unknown := NewRecognizers(nil)
	if len(unknown) != 0 {
		t.Fatalf("expected unknown empty, got %v", unknown)
	}
	if len(recs) != 4 {
		t.Fatalf("expected 4 safe recognizers, got %d", len(recs))
	}
}

func TestNewRecognizers_All(t *testing.T) {
	t.Parallel()

	recs, unknown := NewRecognizers([]string{"all"})
	if len(unknown) != 0 {
		t.Fatalf("expected unknown empty, got %v", unknown)
	}
	if len(recs) < 10 {
		t.Fatalf("expected many recognizers for all, got %d", len(recs))
	}
}
