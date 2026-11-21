// Command server renders the WebSocket authorization-bypass provenance
// report page from the SQLite store.
package main

import (
	_ "embed"
	"flag"
	"html/template"
	"log"
	"net/http"

	"wsauthz/internal/store"
)

//go:embed page.html
var pageHTML string

func main() {
	dbPath := flag.String("db", "artifacts/wsauthz.db", "SQLite database path")
	addr := flag.String("addr", "127.0.0.1:8080", "listen address")
	flag.Parse()

	st, err := store.Open(*dbPath)
	if err != nil {
		log.Fatalf("open store: %v", err)
	}
	defer st.Close()

	tpl := template.Must(template.New("page").Funcs(template.FuncMap{
		"verdictClass": verdictClass,
	}).Parse(pageHTML))

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		rep, err := st.LoadReport()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := tpl.Execute(w, rep); err != nil {
			log.Printf("render: %v", err)
		}
	})

	log.Printf("serving provenance report on http://%s (db=%s)", *addr, *dbPath)
	log.Fatal(http.ListenAndServe(*addr, nil))
}

func verdictClass(v string) string {
	switch v {
	case "bypass_detected":
		return "bad"
	case "no_bypass":
		return "good"
	default:
		return "warn"
	}
}
