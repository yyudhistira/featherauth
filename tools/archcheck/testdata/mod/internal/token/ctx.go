package token

import (
	"net/http"
	"time"
)

type api struct {
	*http.Client
}

func Ctx() {
	c := &http.Client{Timeout: time.Second}
	_, _ = c.Get("http://example.com")
	_, _ = c.Head("http://example.com")
	a := api{Client: c}
	_, _ = a.Post("http://example.com", "text/plain", nil)
	_, _ = a.PostForm("http://example.com", nil)
	req, _ := http.NewRequestWithContext(nil, "GET", "http://example.com", nil)
	_, _ = c.Do(req)
}
