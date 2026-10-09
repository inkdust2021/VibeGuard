## Rule System (Recommended Priority)

1) **Keyword list**: exact substring matching (good for names, project codenames, key fragments, etc.).
2) **Rule lists (`.vgrules`)**: line-based `keyword/regex` rules (good for common patterns like email/phone/IDs; supports local upload and subscriptions).
3) **NER entity recognition**: detects entities like `PERSON / ORG / LOCATION` via **external Presidio Analyzer** (VibeGuard does not bundle models).

Admin UI entry:

- `http://127.0.0.1:28657/manager/`
- Rule lists: `#/rule_lists`
- Keyword list: `#/keywords`
- NER: `#/ner`

---

## Rule Lists (`.vgrules`)

Rule files are parsed line by line. Blank lines and comment lines are ignored (starting with `#`, `//`, `;`, or `!`).

- `keyword <CATEGORY> <TEXT...>`: exact string match (case-sensitive)
- `regex   <CATEGORY> <RE2_PATTERN...>`: Go RE2 regex match  
  If the regex contains capture groups, VibeGuard replaces the **first capture group** range first (safer, avoids redacting parameter names together with values).

Sample file: `docs/rule_lists.sample.vgrules`

### Subscriptions

Rule list subscriptions only require a URL. VibeGuard still enforces basic safety checks (size limit, text parsing/regex compilation) and caches the fetched content locally.

Subscription cache directory: `~/.vibeguard/rules/subscriptions/`

---

## NER (Named Entity Recognition)

NER detects entities and replaces them with placeholders. It is best for content that is hard to enumerate as rules (e.g., personal names / organizations / locations).
For common PII (email/phone/card numbers, etc.), `.vgrules` is usually a better fit.

### Engine: Presidio Only

VibeGuard only provides the wiring. You bring your own Presidio Analyzer deployment (local / docker / sidecar) and point VibeGuard to its API.

### Config

YAML keys:

- `patterns.ner.enabled`: enable/disable NER
- `patterns.ner.presidio_url`: Presidio Analyzer base URL (VibeGuard calls `/analyze` automatically)
- `patterns.ner.language`: `auto` / `en` / `zh` / `...`
- `patterns.ner.entities`: entity list (empty = default safe set)
- `patterns.ner.min_score`: `0~1` (0 = Presidio default)

Example:

```yaml
patterns:
  ner:
    enabled: true
    presidio_url: "http://127.0.0.1:5001"
    language: "auto"
    entities: ["PERSON", "ORG", "LOCATION"]
    min_score: 0.5
```

---

## Development & Debugging

### Key Entry Points (Config → Effective Behavior)

1. Config: `internal/config/NERConfig` (YAML: `patterns.ner.*`) and `patterns.rule_lists`
2. Admin API: `/manager/api/ner` and `/manager/api/rule_lists` (see `internal/admin/`)
3. Proxy wiring: `internal/proxy/proxy.go` → `applyConfig()` merges keyword list + rule lists + NER
4. Redaction pipeline: `internal/pii_next/pipeline.Pipeline` (greedy selection by priority to avoid overlapping fragment replacements)

### Common Commands

```bash
go test ./...
go test ./internal/pii_next/...
```

## Automatic Cleanup

See [automatic cleanup settings](AUTO_CLEANUP.md) for runtime log rotation and encrypted session WAL compaction, including independent switches, intervals, defaults, and project overrides.
