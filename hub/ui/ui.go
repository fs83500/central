// Package ui embeds the hub dashboard (go:embed — zero npm, SPEC §4).
package ui

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed static
var staticFS embed.FS

// Static returns the /static/ file system (CSS, JS, fonts…).
func Static() http.Handler {
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		panic(err)
	}
	return http.StripPrefix("/static/", http.FileServer(http.FS(sub)))
}

// Page renders one of the embedded HTML pages at its final path.
func Page(name string) http.Handler {
	b, err := staticFS.ReadFile("static/" + name)
	if err != nil {
		panic(err)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		_, _ = w.Write(b)
	})
}
