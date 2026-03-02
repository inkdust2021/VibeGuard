package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/inkdust2021/vibeguard/internal/pii_next/keywords"
	"github.com/inkdust2021/vibeguard/internal/pii_next/pipeline"
	"github.com/inkdust2021/vibeguard/internal/pii_next/presidio"
	"github.com/inkdust2021/vibeguard/internal/pii_next/recognizer"
	"github.com/inkdust2021/vibeguard/internal/session"
)

// 示例：
//
//	echo "hi I'm Samuel Porter. My email is Samuel@gmail.com." | go run ./internal/pii_next/demo --keyword "Samuel Porter"
func main() {
	var (
		textFlag       = flag.String("text", "", "要脱敏的文本（留空则从 stdin 读取）")
		keywordFlags   = flag.String("keyword", "", "关键词（可用逗号分隔多个，例如: \"foo,bar\"）")
		showOriginal   = flag.Bool("show-original", false, "输出命中详情时显示原文（默认不显示）")
		deterministic  = flag.Bool("deterministic", true, "使用稳定占位符（HMAC 固定 key；便于对比测试）")
		sessionTTL     = flag.Duration("ttl", 1*time.Hour, "会话映射有效期")
		sessionMaxSize = flag.Int("max", 100000, "会话映射最大条目数")
	)
	flag.Parse()

	input := *textFlag
	if input == "" {
		b, err := io.ReadAll(os.Stdin)
		if err != nil {
			fmt.Fprintln(os.Stderr, "读取 stdin 失败：", err)
			os.Exit(2)
		}
		input = string(b)
	}

	sess := session.NewManager(*sessionTTL, *sessionMaxSize)
	defer sess.Close()
	if *deterministic {
		key32 := make([]byte, 32)
		for i := range key32 {
			key32[i] = byte(i)
		}
		_ = sess.SetDeterministicPlaceholders(true, key32)
	}

	var recs []recognizer.Recognizer
	if *keywordFlags != "" {
		var kws []keywords.Keyword
		for _, k := range strings.Split(*keywordFlags, ",") {
			k = strings.TrimSpace(k)
			if k == "" {
				continue
			}
			kws = append(kws, keywords.Keyword{Text: k, Category: "TEXT"})
		}
		if len(kws) > 0 {
			recs = append(recs, keywords.New(kws))
		}
	}
	recs = append(recs, presidio.DefaultRecognizers()...)

	p := pipeline.New(sess, "__VG_", recs...)
	out, matches := p.RedactWithMatches([]byte(input))

	fmt.Println(string(out))

	type item struct {
		Category    string `json:"category"`
		Placeholder string `json:"placeholder"`
		Start       int    `json:"start"`
		End         int    `json:"end"`
		Original    string `json:"original,omitempty"`
	}
	items := make([]item, 0, len(matches))
	for _, m := range matches {
		it := item{
			Category:    m.Category,
			Placeholder: m.Placeholder,
			Start:       m.Start,
			End:         m.End,
		}
		if *showOriginal {
			it.Original = m.Original
		}
		items = append(items, it)
	}
	b, _ := json.MarshalIndent(items, "", "  ")
	fmt.Println(string(b))
}
