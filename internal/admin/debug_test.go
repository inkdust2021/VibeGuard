package admin

import (
	"net/http"
	"testing"
	"time"
)

func TestDebugStore_BasicFlow(t *testing.T) {
	s := NewDebugStore(2)
	if s == nil {
		t.Fatalf("NewDebugStore returned nil")
	}

	st := s.Status()
	if st.Enabled {
		t.Fatalf("expected disabled by default")
	}
	if st.MaxBodyBytes <= 0 {
		t.Fatalf("expected positive MaxBodyBytes")
	}

	now := time.Now()
	s.UpsertRequest(1, DebugRequestCapture{
		Time:            now,
		Host:            "example.com",
		Method:          "POST",
		Path:            "/v1/test",
		URL:             "https://example.com/v1/test?x=1",
		ContentType:     "application/json",
		ContentEncoding: "zstd",
		HeadersOriginal: http.Header{
			"Authorization": []string{"Bearer secret"},
		},
		HeadersForwarded: http.Header{
			"Accept-Encoding": []string{"identity"},
		},
		BodyOriginalText:   `{"a":"b"}`,
		BodyOriginalBytes:  9,
		BodyForwardedText:  `{"a":"__VG_TEXT_x__"}`,
		BodyForwardedBytes: 20,
	})

	s.UpsertResponse(1, DebugResponseCapture{
		ContentType: "text/event-stream",
		Status:      200,
		HeadersOriginal: http.Header{
			"Set-Cookie": []string{"session=abc"},
		},
		HeadersForwarded: http.Header{
			"Content-Type": []string{"text/event-stream"},
		},
		BodyUpstreamText:  "data: __VG_TEXT_x__\n\n",
		BodyUpstreamBytes: 20,
		BodyClientText:    "data: b\n\n",
		BodyClientBytes:   10,
	})

	ev, ok := s.Get(1)
	if !ok {
		t.Fatalf("expected event")
	}
	if ev.ID != 1 || ev.Host != "example.com" || ev.Method != "POST" {
		t.Fatalf("unexpected meta: %+v", ev)
	}
	if ev.Response.ResponseStatus != 200 {
		t.Fatalf("expected status 200, got %d", ev.Response.ResponseStatus)
	}

	s.UpsertRequest(2, DebugRequestCapture{Time: now})
	s.UpsertRequest(3, DebugRequestCapture{Time: now})
	// max=2：应丢弃最旧的 1
	if _, ok := s.Get(1); ok {
		t.Fatalf("expected event 1 to be trimmed")
	}
}

func TestMaskSensitiveHeaders(t *testing.T) {
	h := http.Header{
		"Authorization": []string{"Bearer abcdef"},
		"X-Api-Key":     []string{"k-123"},
		"X-NotSecret":   []string{"ok"},
		"My-Token":      []string{"t-xyz"},
	}
	m := MaskSensitiveHeaders(h)
	if m.Get("X-NotSecret") != "ok" {
		t.Fatalf("expected X-NotSecret to remain, got %q", m.Get("X-NotSecret"))
	}
	if m.Get("Authorization") == "" || m.Get("Authorization") == "Bearer abcdef" {
		t.Fatalf("expected Authorization to be masked, got %q", m.Get("Authorization"))
	}
	if m.Get("X-Api-Key") == "k-123" {
		t.Fatalf("expected X-Api-Key to be masked, got %q", m.Get("X-Api-Key"))
	}
	if m.Get("My-Token") == "t-xyz" {
		t.Fatalf("expected My-Token to be masked, got %q", m.Get("My-Token"))
	}
}
