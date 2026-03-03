package nlp

import (
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/inkdust2021/vibeguard/internal/pii_next/recognizer"
)

type heuristicRecognizer struct {
	enabledEntities map[string]struct{}
}

func newHeuristicRecognizer(opts Options) *heuristicRecognizer {
	return &heuristicRecognizer{
		enabledEntities: normalizeEntities(opts.Entities),
	}
}

func (r *heuristicRecognizer) Name() string { return "nlp-heuristic" }

func (r *heuristicRecognizer) Recognize(input []byte) []recognizer.Match {
	if r == nil || len(input) == 0 {
		return nil
	}

	var out []recognizer.Match

	if r.enabled("PERSON") {
		out = append(out, r.recognizeEnglishFullNames(input)...)
		out = append(out, r.recognizeChineseNames(input)...)
	}
	if r.enabled("ORG") {
		out = append(out, r.recognizeOrganizations(input)...)
	}
	if r.enabled("LOCATION") {
		out = append(out, r.recognizeLocations(input)...)
	}
	return out
}

func (r *heuristicRecognizer) enabled(name string) bool {
	if r == nil || r.enabledEntities == nil {
		return false
	}
	_, ok := r.enabledEntities[name]
	return ok
}

var (
	// 英文人名：仅在“自我介绍”上下文中识别，避免把常见标题词组误判为 PERSON。
	// 例：I'm John Smith / my name is John Smith / this is John Smith
	reEnglishNameWithIntro = regexp.MustCompile(`\b(?i:(?:i['’]m|i am|my name is|this is))\s+([A-Z][a-z]{1,20}(?:[-'][A-Z][a-z]{1,20})?\s+[A-Z][a-z]{1,20}(?:[-'][A-Z][a-z]{1,20})?(?:\s+[A-Z][a-z]{1,20}(?:[-'][A-Z][a-z]{1,20})?)?)\b`)

	// 中文姓名：仅在“自我介绍/字段”上下文中识别，避免对任意“姓+1字/2字”进行泛化匹配造成误报。
	// 例：我叫张三 / 我是欧阳娜娜 / 姓名：张三
	reChineseNameWithIntro = regexp.MustCompile(`(?:我叫|我是|名叫|叫做|姓名[:：]?\s*|联系人[:：]?\s*|收件人[:：]?\s*|发件人[:：]?\s*|签名[:：]?\s*|作者[:：]?\s*|负责人[:：]?\s*)([\p{Han}]{2,4})`)

	// 中文姓名：常见称谓后缀（张三老师 / 李四先生），用于更贴近真实对话场景。
	// 注意：仍会经过 looksLikeChineseFullName 校验，避免把“北京老师”之类误判为 PERSON。
	reChineseNameWithTitleSuffix = regexp.MustCompile(`([\p{Han}]{2,4})(?:先生|女士|同学|老师|博士|教授)`)

	// 中文姓名：机构/组织的某某（清华大学的张三 / 某某公司的李四）
	reChineseNameAfterOrgOf = regexp.MustCompile(`(?:大学|学院|研究院|研究所|公司|集团|银行|医院)的([\p{Han}]{2,4})`)

	reEnglishOrg = regexp.MustCompile(`\b[A-Z][A-Za-z0-9&.\-]{1,40}(?:\s+[A-Z][A-Za-z0-9&.\-]{1,40}){0,5}\s+(?:Inc|LLC|Ltd|Limited|Corporation|Corp|Company|Co)\.?\b`)

	// 中文组织/机构：通过“常见后缀”识别。
	//
	// 为什么不是用 (?:^|[^\p{Han}]) 这种边界？
	// - 中文正文往往是连续汉字，严格的“非汉字边界”会导致在句子中几乎识别不到（例如：我在清华大学读书）。
	// - 这里用“常见分隔字符（非汉字）或常见介词/动词末字（在/于/到/自/入...）”作为轻量边界，兼顾可用性与误报控制。
	reChineseOrgAtStart = regexp.MustCompile(`^([\p{Han}]{2,30}(?:有限责任公司|有限公司|集团|公司|大学|学院|研究院|研究所|医院|银行))`)
	reChineseOrg        = regexp.MustCompile(`(?:[^\p{Han}]|[在于自从到去来往至入进加])([\p{Han}]{2,30}(?:有限责任公司|有限公司|集团|公司|大学|学院|研究院|研究所|医院|银行))`)

	reEnglishLocation = regexp.MustCompile(`\b[A-Z][a-z]{2,}(?:\s+[A-Z][a-z]{2,}){0,2},\s*[A-Z]{2}\b`)

	// 中文地点：行政区划后缀识别（北京市 / 浦东新区 / 广东省 等）
	reChineseLocationAtStart = regexp.MustCompile(`^([\p{Han}]{2,10}(?:省|市|自治区|州|县|区))`)
	reChineseLocation        = regexp.MustCompile(`(?:[^\p{Han}]|[在于自从到去来往至住居])([\p{Han}]{2,10}(?:省|市|自治区|州|县|区))`)

	// 中文地点：直辖市/港澳台（很多人习惯写“我在上海”，不写“上海市”）
	reChineseMunicipalityAtStart = regexp.MustCompile(`^((?:北京|上海|天津|重庆|香港|澳门|台湾))`)
	reChineseMunicipality        = regexp.MustCompile(`(?:[^\p{Han}]|[在于自从到去来往至住居])((?:北京|上海|天津|重庆|香港|澳门|台湾))`)
)

func (r *heuristicRecognizer) recognizeEnglishFullNames(input []byte) []recognizer.Match {
	locs := reEnglishNameWithIntro.FindAllSubmatchIndex(input, -1)
	if len(locs) == 0 {
		return nil
	}
	out := make([]recognizer.Match, 0, len(locs))
	for _, loc := range locs {
		// group 1
		if len(loc) < 4 {
			continue
		}
		start, end := loc[2], loc[3]
		if start < 0 || end < 0 || start >= end || end > len(input) {
			continue
		}
		out = append(out, recognizer.Match{
			Start:    start,
			End:      end,
			Category: "PERSON",
			Priority: 90,
			Source:   r.Name(),
		})
	}
	return out
}

func (r *heuristicRecognizer) recognizeOrganizations(input []byte) []recognizer.Match {
	var out []recognizer.Match

	locs := reEnglishOrg.FindAllIndex(input, -1)
	for _, loc := range locs {
		start, end := loc[0], loc[1]
		if start < 0 || end < 0 || start >= end || end > len(input) {
			continue
		}
		out = append(out, recognizer.Match{
			Start:    start,
			End:      end,
			Category: "ORG",
			Priority: 85,
			Source:   r.Name(),
		})
	}

	appendOrgGroup := func(locs [][]int) {
		for _, loc := range locs {
			// group 1
			if len(loc) < 4 {
				continue
			}
			start, end := loc[2], loc[3]
			if start < 0 || end < 0 || start >= end || end > len(input) {
				continue
			}
			name, consumed := trimChineseOrgContextPrefix(string(input[start:end]))
			if name == "" {
				continue
			}
			start += consumed
			end = start + len(name)
			if start < 0 || end < 0 || start >= end || end > len(input) {
				continue
			}
			if !looksLikeChineseOrgName(name) {
				continue
			}
			out = append(out, recognizer.Match{
				Start:    start,
				End:      end,
				Category: "ORG",
				Priority: 85,
				Source:   r.Name(),
			})
		}
	}
	appendOrgGroup(reChineseOrgAtStart.FindAllSubmatchIndex(input, -1))
	appendOrgGroup(reChineseOrg.FindAllSubmatchIndex(input, -1))

	return out
}

func (r *heuristicRecognizer) recognizeLocations(input []byte) []recognizer.Match {
	var out []recognizer.Match

	locs := reEnglishLocation.FindAllIndex(input, -1)
	for _, loc := range locs {
		start, end := loc[0], loc[1]
		if start < 0 || end < 0 || start >= end || end > len(input) {
			continue
		}
		out = append(out, recognizer.Match{
			Start:    start,
			End:      end,
			Category: "LOCATION",
			Priority: 80,
			Source:   r.Name(),
		})
	}

	appendLocationGroup := func(locs [][]int, validate func(string) bool) {
		for _, loc := range locs {
			// group 1
			if len(loc) < 4 {
				continue
			}
			start, end := loc[2], loc[3]
			if start < 0 || end < 0 || start >= end || end > len(input) {
				continue
			}
			name := string(input[start:end])
			if validate != nil {
				var consumed int
				name, consumed = trimChineseLocationContextPrefix(name)
				if name == "" {
					continue
				}
				start += consumed
				end = start + len(name)
				if start < 0 || end < 0 || start >= end || end > len(input) {
					continue
				}
				if !validate(name) {
					continue
				}
			}
			out = append(out, recognizer.Match{
				Start:    start,
				End:      end,
				Category: "LOCATION",
				Priority: 80,
				Source:   r.Name(),
			})
		}
	}

	appendLocationGroup(reChineseLocationAtStart.FindAllSubmatchIndex(input, -1), looksLikeChineseLocationName)
	appendLocationGroup(reChineseLocation.FindAllSubmatchIndex(input, -1), looksLikeChineseLocationName)
	appendLocationGroup(reChineseMunicipalityAtStart.FindAllSubmatchIndex(input, -1), nil)
	appendLocationGroup(reChineseMunicipality.FindAllSubmatchIndex(input, -1), nil)

	return out
}

var chineseSurnameSingles = func() map[rune]struct{} {
	// 取常见姓氏集合（运行期去重），用于“低误报”的中文姓名启发式识别。
	// 说明：此处不追求完整姓氏库，避免规则过宽导致误伤。
	const surnames = "赵钱孙李周吴郑王冯陈蒋沈韩杨朱秦许何吕施张孔曹严华金魏陶姜戚谢邹云苏潘葛范彭郎鲁韦昌马苗凤花方俞任袁柳鲍史唐费岑薛雷贺倪汤滕殷罗毕郝邬安常乐于时傅卞齐康伍余元卜顾孟黄和穆萧尹姚邵汪祁毛禹狄米贝明臧伏成戴谈宋茅庞熊纪舒屈项祝董梁杜阮蓝闵席季麻强贾路娄危江童颜郭梅盛林刁钟徐邱骆高夏蔡田樊胡凌霍虞万支柯昝管卢莫经房裘缪干解应宗丁宣邓郁单杭洪包诸左石崔吉钮龚程邢滑裴陆荣翁荀羊惠甄曲家封芮储靳汲邴糜松井段富巫乌焦巴弓牧隗山谷车侯宓蓬全郗班仰秋仲伊宫宁仇栾暴甘厉戎祖武符刘景詹束龙叶幸司黎薄印宿白怀蒲邰从鄂索咸籍赖卓蔺屠蒙池乔阴胥能苍双闻党翟贡劳逄姬申扶堵冉宰郦雍桑桂濮牛寿通边扈燕冀浦尚农温别庄晏柴瞿阎充慕连茹习宦艾鱼容向古易慎戈廖庾终暨居衡步都耿满弘匡国文寇广禄阙东欧殳沃利蔚越隆师巩厍聂晁勾敖融冷訾辛阚那简饶空曾毋沙乜养鞠须丰巢关蒯相查后荆红游竺权逯盖益桓公仉督岳帅缑亢况钦涂法汝鄢"
	m := make(map[rune]struct{}, len([]rune(surnames)))
	for _, r := range []rune(surnames) {
		m[r] = struct{}{}
	}
	return m
}()

var chineseSurnameDoubles = map[string]struct{}{
	"欧阳": {}, "司马": {}, "上官": {}, "诸葛": {}, "东方": {}, "皇甫": {}, "尉迟": {}, "公羊": {}, "赫连": {}, "澹台": {}, "公冶": {}, "宗政": {}, "濮阳": {}, "淳于": {}, "单于": {}, "太叔": {}, "申屠": {}, "公孙": {}, "仲孙": {}, "轩辕": {}, "令狐": {}, "钟离": {}, "宇文": {}, "长孙": {}, "慕容": {}, "司徒": {}, "司空": {}, "夏侯": {},
}

func (r *heuristicRecognizer) recognizeChineseNames(input []byte) []recognizer.Match {
	var out []recognizer.Match

	appendNameGroup := func(locs [][]int, allowTailTrim bool) {
		for _, loc := range locs {
			// group 1
			if len(loc) < 4 {
				continue
			}
			start, end := loc[2], loc[3]
			if start < 0 || end < 0 || start >= end || end > len(input) {
				continue
			}
			nameStart := start
			if allowTailTrim {
				if off := trimToChineseFullNameTailBytes(input[start:end]); off > 0 {
					nameStart += off
				}
			}
			if nameStart < 0 || nameStart >= end || end > len(input) {
				continue
			}
			name := string(input[nameStart:end])
			if !looksLikeChineseFullName(name) {
				continue
			}
			out = append(out, recognizer.Match{
				Start:    nameStart,
				End:      end,
				Category: "PERSON",
				Priority: 90,
				Source:   r.Name(),
			})
		}
	}

	appendNameGroup(reChineseNameWithIntro.FindAllSubmatchIndex(input, -1), false)
	appendNameGroup(reChineseNameWithTitleSuffix.FindAllSubmatchIndex(input, -1), true)
	appendNameGroup(reChineseNameAfterOrgOf.FindAllSubmatchIndex(input, -1), false)

	if len(out) == 0 {
		return nil
	}
	return out
}

func looksLikeChineseFullName(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	rs := []rune(s)
	if len(rs) < 2 || len(rs) > 4 {
		return false
	}

	// 双姓优先
	if len(rs) >= 3 {
		if _, ok := chineseSurnameDoubles[string(rs[0:2])]; ok {
			// 双姓 + 1~2 字名（共 3~4 字）
			return len(rs) == 3 || len(rs) == 4
		}
	}
	if _, ok := chineseSurnameSingles[rs[0]]; ok {
		// 单姓 + 1~2 字名（共 2~3 字）
		return len(rs) == 2 || len(rs) == 3
	}
	return false
}

var chineseOrgGenericFull = map[string]struct{}{
	"本公司":  {},
	"该公司":  {},
	"此公司":  {},
	"贵公司":  {},
	"我公司":  {},
	"你公司":  {},
	"他公司":  {},
	"她公司":  {},
	"其公司":  {},
	"某公司":  {},
	"我们公司": {},
	"你们公司": {},
	"他们公司": {},
	"她们公司": {},
	"咱们公司": {},
	"本集团":  {},
	"该集团":  {},
	"此集团":  {},
	"贵集团":  {},
	"某集团":  {},
	"我们集团": {},
	"你们集团": {},
	"他们集团": {},
	"她们集团": {},
	"咱们集团": {},
}

var chineseOrgGenericPrefixes = []string{
	"本", "该", "此", "贵", "某",
	"我", "你", "他", "她", "其",
	"我们", "你们", "他们", "她们", "咱们",
}

func looksLikeChineseOrgName(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	if _, ok := chineseOrgGenericFull[s]; ok {
		return false
	}
	rs := []rune(s)
	if len(rs) < 4 || len(rs) > 32 {
		return false
	}
	// 短字符串下，排除常见泛指前缀（我们公司/某公司/本集团 等）
	if len(rs) <= 6 {
		for _, p := range chineseOrgGenericPrefixes {
			if strings.HasPrefix(s, p) {
				return false
			}
		}
	}
	return true
}

func looksLikeChineseLocationName(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	rs := []rune(s)
	if len(rs) < 2 || len(rs) > 16 {
		return false
	}
	// “大城市/小城市”这类更可能是泛指而非具体地名。
	if strings.HasSuffix(s, "城市") {
		return false
	}
	return true
}

// trimToChineseFullNameTailBytes 尝试从右侧提取一个“看起来像中文全名”的尾部子串。
// 用于处理类似 “联系张三” 这类场景，避免 PERSON 规则被前缀动词污染。
// 返回需要从开头跳过的字节数（0 表示不跳过/未命中）。
func trimToChineseFullNameTailBytes(b []byte) int {
	if len(b) == 0 {
		return 0
	}
	off := 0
	for off < len(b) {
		s := string(b[off:])
		if looksLikeChineseFullName(s) {
			return off
		}
		_, size := utf8.DecodeRune(b[off:])
		if size <= 0 || size > len(b)-off {
			break
		}
		off += size
	}
	return 0
}

// trimChineseOrgContextPrefix 尽量移除中文组织名称前的常见上下文前缀（时间/代词/礼貌词/动词/介词等）。
// 返回（去前缀后的字符串，去除的字节数）。
func trimChineseOrgContextPrefix(s string) (string, int) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", 0
	}

	// 顺序很重要：优先匹配更长的前缀。
	prefixes := []string{
		"现在", "目前", "正在", "刚刚", "刚才", "今天", "昨天", "明天",
		"我们", "你们", "他们", "她们", "咱们", "我", "你", "他", "她", "其",
		"麻烦", "帮忙", "帮我", "欢迎", "请", "联系", "加入", "进入", "来到", "回到", "前往", "来自",
		"在", "于", "从", "到",
	}

	consumed := 0
	for i := 0; i < 6; i++ { // 防止极端输入导致死循环；最多剥离 6 次
		changed := false
		for _, p := range prefixes {
			if strings.HasPrefix(s, p) && len(s) > len(p) {
				s = s[len(p):]
				consumed += len(p)
				changed = true
				break
			}
		}
		if !changed {
			break
		}
	}
	return strings.TrimSpace(s), consumed
}

// trimChineseLocationContextPrefix 尽量移除中文地点名称前的常见上下文前缀（时间/字段名/介词等）。
// 返回（去前缀后的字符串，去除的字节数）。
func trimChineseLocationContextPrefix(s string) (string, int) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", 0
	}
	prefixes := []string{
		"现在", "目前", "正在", "刚刚", "刚才", "今天", "昨天", "明天",
		"所在地", "地址", "位置",
		"坐落于", "位于", "来自", "前往", "来到", "回到",
		"居住在", "住在", "现居", "现住",
		"在", "于", "从", "到",
	}

	consumed := 0
	for i := 0; i < 6; i++ {
		changed := false
		for _, p := range prefixes {
			if strings.HasPrefix(s, p) && len(s) > len(p) {
				s = s[len(p):]
				consumed += len(p)
				changed = true
				break
			}
		}
		if !changed {
			break
		}
	}
	return strings.TrimSpace(s), consumed
}
