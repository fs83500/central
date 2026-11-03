// prefixedRedirect rewrites outbound Location headers so redirects emitted
// by the hub (e.g. "hosts", "login?err=…") stay INSIDE the preview proxy
// prefix (HUB_UI_PREFIX, dev only). Without it Go resolves relative targets
// against the stripped path and the browser would land outside the prefix.
package main

import (
	"bufio"
	"net"
	"net/http"
)

type prefixedRedirect struct {
	http.ResponseWriter
	prefix string
}

func (w *prefixedRedirect) WriteHeader(code int) {
	if loc := w.Header().Get("Location"); loc != "" && loc[0] == '/' {
		w.Header().Set("Location", w.prefix+loc)
	}
	w.ResponseWriter.WriteHeader(code)
}

// Hijack forwards to the underlying ResponseWriter. The agent WebSocket
// (gorilla) needs to hijack the TCP connection for the upgrade; without
// this method the type assertion inside gorilla fails and the WS returns
// a silent 500 behind the preview prefix wrapper.
func (w *prefixedRedirect) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := w.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, http.ErrNotSupported
}

// Flush forwards to the underlying ResponseWriter when it supports it.
func (w *prefixedRedirect) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}