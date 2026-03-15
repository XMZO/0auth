package i18n

import "strings"

const defaultLang = "zh"

type Translator struct {
	messages map[string]map[string]string
}

func New() *Translator {
	return &Translator{
		messages: map[string]map[string]string{
			"zh": zhMessages(),
			"en": enMessages(),
		},
	}
}

func (t *Translator) Text(lang string, key string) string {
	lang = normalizeLang(lang)
	if lang == "" {
		lang = defaultLang
	}
	if bundle, ok := t.messages[lang]; ok {
		if value, ok := bundle[key]; ok {
			return value
		}
	}
	if value, ok := t.messages[defaultLang][key]; ok {
		return value
	}
	return key
}

func normalizeLang(raw string) string {
	value := strings.ToLower(strings.TrimSpace(raw))
	switch {
	case value == "zh", strings.HasPrefix(value, "zh-"), strings.HasPrefix(value, "zh_"):
		return "zh"
	case value == "en", strings.HasPrefix(value, "en-"), strings.HasPrefix(value, "en_"):
		return "en"
	default:
		return ""
	}
}
