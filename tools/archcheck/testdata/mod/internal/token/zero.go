package token

import (
	"net/http"
	"time"
)

type wrapper struct {
	http.Client
}

type holder struct {
	srv http.Server
	c   *http.Client
}

var pkgClient http.Client

func Zero() {
	var c http.Client
	var srv http.Server
	_ = srv.ListenAndServe()
	_ = c
	_ = &http.Client{Timeout: 0}
	_ = &http.Server{ReadTimeout: 0, WriteTimeout: time.Second, IdleTimeout: time.Second}
	var ok = http.Client{Timeout: time.Second}
	_ = ok
	_ = wrapper{}
	_ = holder{}
}
