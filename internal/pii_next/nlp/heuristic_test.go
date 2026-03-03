package nlp

import (
	"bytes"
	"testing"

	"github.com/inkdust2021/vibeguard/internal/pii_next/recognizer"
)

func findMatch(t *testing.T, in []byte, category, wantSubstr string, ms []recognizer.Match) {
	t.Helper()
	for _, m := range ms {
		if m.Category != category {
			continue
		}
		if m.Start < 0 || m.End < 0 || m.Start >= m.End || m.End > len(in) {
			continue
		}
		if string(in[m.Start:m.End]) == wantSubstr {
			return
		}
	}
	t.Fatalf("expected %s match %q not found; got=%v", category, wantSubstr, ms)
}

func TestHeuristicRecognizer_EnglishPerson(t *testing.T) {
	in := []byte("hi I'm Samuel Porter. My email is Samuel@gmail.com.")
	r := newHeuristicRecognizer(Options{Entities: []string{"PERSON"}})
	ms := r.Recognize(in)
	findMatch(t, in, "PERSON", "Samuel Porter", ms)
}

func TestHeuristicRecognizer_ChinesePerson_WithIntroducer(t *testing.T) {
	in := []byte("你好，我叫张三。")
	r := newHeuristicRecognizer(Options{Entities: []string{"PERSON"}})
	ms := r.Recognize(in)
	findMatch(t, in, "PERSON", "张三", ms)
}

func TestHeuristicRecognizer_ChinesePerson_BoundaryAvoidsLongPhrase(t *testing.T) {
	in := []byte("王者荣耀")
	r := newHeuristicRecognizer(Options{Entities: []string{"PERSON"}})
	ms := r.Recognize(in)
	for _, m := range ms {
		if m.Category == "PERSON" && bytes.Contains(in[m.Start:m.End], []byte("王")) {
			t.Fatalf("unexpected PERSON match: %q (%v)", string(in[m.Start:m.End]), m)
		}
	}
}

func TestHeuristicRecognizer_ChinesePerson_IntroducerAvoidsFourRunePhraseWithSingleSurname(t *testing.T) {
	in := []byte("我是王者荣耀。")
	r := newHeuristicRecognizer(Options{Entities: []string{"PERSON"}})
	ms := r.Recognize(in)
	for _, m := range ms {
		if m.Category == "PERSON" {
			t.Fatalf("unexpected PERSON match: %q (%v)", string(in[m.Start:m.End]), m)
		}
	}
}

func TestHeuristicRecognizer_ChinesePerson_DoubleSurname(t *testing.T) {
	in := []byte("我是欧阳娜娜。")
	r := newHeuristicRecognizer(Options{Entities: []string{"PERSON"}})
	ms := r.Recognize(in)
	findMatch(t, in, "PERSON", "欧阳娜娜", ms)
}

func TestHeuristicRecognizer_OrgAndLocation(t *testing.T) {
	in := []byte("OpenAI Inc is based in San Francisco, CA.")
	r := newHeuristicRecognizer(Options{Entities: []string{"ORG", "LOCATION"}})
	ms := r.Recognize(in)
	findMatch(t, in, "ORG", "OpenAI Inc", ms)
	findMatch(t, in, "LOCATION", "San Francisco, CA", ms)
}

func TestHeuristicRecognizer_ChineseOrgAndLocation_InSentence(t *testing.T) {
	in := []byte("我在清华大学读书，现在在北京市工作。")
	r := newHeuristicRecognizer(Options{Entities: []string{"ORG", "LOCATION"}})
	ms := r.Recognize(in)
	findMatch(t, in, "ORG", "清华大学", ms)
	findMatch(t, in, "LOCATION", "北京市", ms)
}

func TestHeuristicRecognizer_ChineseLocation_MunicipalityWithoutSuffix(t *testing.T) {
	in := []byte("我在上海工作。")
	r := newHeuristicRecognizer(Options{Entities: []string{"LOCATION"}})
	ms := r.Recognize(in)
	findMatch(t, in, "LOCATION", "上海", ms)
}

func TestHeuristicRecognizer_ChineseOrg_AvoidGenericCompany(t *testing.T) {
	in := []byte("我们公司今天发版。")
	r := newHeuristicRecognizer(Options{Entities: []string{"ORG"}})
	ms := r.Recognize(in)
	for _, m := range ms {
		if m.Category == "ORG" {
			t.Fatalf("unexpected ORG match: %q (%v)", string(in[m.Start:m.End]), m)
		}
	}
}

func TestHeuristicRecognizer_ChinesePerson_AfterOrgOf(t *testing.T) {
	in := []byte("我是清华大学的张三。")
	r := newHeuristicRecognizer(Options{Entities: []string{"PERSON"}})
	ms := r.Recognize(in)
	findMatch(t, in, "PERSON", "张三", ms)
}

func TestHeuristicRecognizer_ChinesePerson_WithTitleSuffix(t *testing.T) {
	in := []byte("请联系张三老师。")
	r := newHeuristicRecognizer(Options{Entities: []string{"PERSON"}})
	ms := r.Recognize(in)
	findMatch(t, in, "PERSON", "张三", ms)
}
