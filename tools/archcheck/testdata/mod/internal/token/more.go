package token

import (
	"log/slog"
	"net/http"
	. "strings"
	"time"
)

var _ = ToUpper

func More() {
	slog.Info("x")
	_ = slog.Default()
	time.Sleep(time.Second)
	<-time.After(time.Second)
	_, _ = http.NewRequest("GET", "http://example.com", nil)
	_ = &http.Client{}
	_ = http.Client{Timeout: time.Second}
	_ = http.ListenAndServe(":0", nil)
	_ = &http.Server{ReadTimeout: time.Second}
	_ = &http.Server{ReadHeaderTimeout: time.Second, WriteTimeout: time.Second, IdleTimeout: time.Second}
	_ = new(http.Client)
	_ = slog.String("k", "v")
	_ = new(http.Server)
}
