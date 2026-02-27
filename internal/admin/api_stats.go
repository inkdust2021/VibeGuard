package admin

import (
	"encoding/json"
	"net/http"
	"time"
)

// StatsResponse represents the stats API response
type StatsResponse struct {
	Proxy struct {
		Status        string `json:"status"`
		UptimeSeconds int64  `json:"uptime_seconds"`
		ListenAddress string `json:"listen_address"`
	} `json:"proxy"`
	Session struct {
		ActiveMappings int `json:"active_mappings"`
		MaxMappings    int `json:"max_mappings"`
		TTLSeconds     int `json:"ttl_seconds"`
	} `json:"session"`
	Requests struct {
		Total    int64 `json:"total"`
		Redacted int64 `json:"redacted"`
		Restored int64 `json:"restored"`
		Errors   int64 `json:"errors"`
	} `json:"requests"`
}

// handleStats returns current statistics
func (a *Admin) handleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	c := a.config.Get()

	resp := StatsResponse{}
	resp.Proxy.Status = "running"
	resp.Proxy.ListenAddress = c.Proxy.Listen

	startTime := a.started.Load()
	if startTime > 0 {
		resp.Proxy.UptimeSeconds = time.Now().Unix() - startTime
	}

	resp.Session.ActiveMappings = a.session.Size()
	resp.Session.MaxMappings = c.Session.MaxMappings

	ttl, err := time.ParseDuration(c.Session.TTL)
	if err == nil {
		resp.Session.TTLSeconds = int(ttl.Seconds())
	}

	resp.Requests.Total = a.stats.TotalRequests.Load()
	resp.Requests.Redacted = a.stats.RedactedRequests.Load()
	resp.Requests.Restored = a.stats.RestoredRequests.Load()
	resp.Requests.Errors = a.stats.Errors.Load()

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(resp)
}

// handleStatsStream returns SSE stream of stats
func (a *Admin) handleStatsStream(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Set SSE headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming not supported", http.StatusInternalServerError)
		return
	}

	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			c := a.config.Get()

			resp := StatsResponse{}
			resp.Proxy.Status = "running"
			resp.Proxy.ListenAddress = c.Proxy.Listen

			startTime := a.started.Load()
			if startTime > 0 {
				resp.Proxy.UptimeSeconds = time.Now().Unix() - startTime
			}

			resp.Session.ActiveMappings = a.session.Size()
			resp.Session.MaxMappings = c.Session.MaxMappings

			ttl, _ := time.ParseDuration(c.Session.TTL)
			resp.Session.TTLSeconds = int(ttl.Seconds())

			resp.Requests.Total = a.stats.TotalRequests.Load()
			resp.Requests.Redacted = a.stats.RedactedRequests.Load()
			resp.Requests.Restored = a.stats.RestoredRequests.Load()
			resp.Requests.Errors = a.stats.Errors.Load()

			data, _ := json.Marshal(resp)
			w.Write([]byte("event: stats\ndata: " + string(data) + "\n\n"))
			flusher.Flush()
		}
	}
}
