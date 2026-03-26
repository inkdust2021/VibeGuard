package proxy

import (
	"net/http"
	"testing"
)

func TestStripWebSocketPerMessageDeflate(t *testing.T) {
	t.Run("只移除压缩扩展并保留其他扩展", func(t *testing.T) {
		h := http.Header{}
		h.Add("Sec-WebSocket-Extensions", "permessage-deflate; client_max_window_bits, x-test")

		if !stripWebSocketPerMessageDeflate(h) {
			t.Fatal("expected header to change")
		}
		if hasWebSocketExtensionToken(h, "Sec-WebSocket-Extensions", "permessage-deflate") {
			t.Fatal("expected permessage-deflate to be removed")
		}
		if !hasWebSocketExtensionToken(h, "Sec-WebSocket-Extensions", "x-test") {
			t.Fatal("expected non-compression extension to be preserved")
		}
	})

	t.Run("只有压缩扩展时直接删除整个头", func(t *testing.T) {
		h := http.Header{}
		h.Set("Sec-WebSocket-Extensions", "permessage-deflate; server_no_context_takeover")

		if !stripWebSocketPerMessageDeflate(h) {
			t.Fatal("expected header to change")
		}
		if got := h.Get("Sec-WebSocket-Extensions"); got != "" {
			t.Fatalf("expected header to be deleted, got %q", got)
		}
	})
}
