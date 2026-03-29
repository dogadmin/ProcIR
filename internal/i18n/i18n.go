package i18n

import "sync"

var (
	mu   sync.RWMutex
	lang = "zh"
)

func SetLang(l string) {
	mu.Lock()
	defer mu.Unlock()
	if l == "en" || l == "zh" {
		lang = l
	}
}

func Lang() string {
	mu.RLock()
	defer mu.RUnlock()
	return lang
}

// T returns the translated string for the given key.
func T(key string) string {
	mu.RLock()
	l := lang
	mu.RUnlock()
	if l == "en" {
		if v, ok := en[key]; ok {
			return v
		}
	}
	if v, ok := zh[key]; ok {
		return v
	}
	return key
}
