package web

import (
	"slices"
	"strconv"
	"strings"
)

// Negotiate picks the locale of a page from an Accept-Language header: the
// supported locale the browser prefers (by quality, then by order), matching
// a regional tag such as nl-BE to its language nl. Without a match it is def.
func Negotiate(header string, supported []string, def string) string {
	type cand struct {
		tag string
		q   float64
		pos int
	}
	var cands []cand
	for i, part := range strings.Split(header, ",") {
		tag, params, _ := strings.Cut(strings.TrimSpace(part), ";")
		tag = strings.ToLower(strings.TrimSpace(tag))
		if tag == "" || tag == "*" {
			continue
		}
		q := 1.0
		for _, p := range strings.Split(params, ";") {
			k, v, ok := strings.Cut(strings.TrimSpace(p), "=")
			if ok && strings.EqualFold(strings.TrimSpace(k), "q") {
				if f, err := strconv.ParseFloat(strings.TrimSpace(v), 64); err == nil {
					q = f
				}
			}
		}
		if q > 0 {
			cands = append(cands, cand{tag, q, i})
		}
	}
	slices.SortStableFunc(cands, func(a, b cand) int {
		switch {
		case a.q > b.q:
			return -1
		case a.q < b.q:
			return 1
		}
		return a.pos - b.pos
	})
	for _, c := range cands {
		for _, s := range supported {
			if strings.EqualFold(s, c.tag) {
				return s
			}
		}
		lang, _, _ := strings.Cut(c.tag, "-")
		for _, s := range supported {
			if strings.EqualFold(s, lang) {
				return s
			}
		}
	}
	return def
}
