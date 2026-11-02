// prefixedRedirect rewrites outbound Location headers so redirects emitted
// by the hub (e.g. "hosts", "login?err=…") stay INSIDE the preview proxy
// prefix (HUB_UI_PREFIX, dev only). Without it Go resolves relative targets
// against the stripped path and the browser would land outside the prefix.
package main

import "net/http"

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
