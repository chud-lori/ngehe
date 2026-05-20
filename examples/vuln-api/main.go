// Deliberately vulnerable demo API for testing ngehe v0.2.
//
// Bugs planted, by detector:
//   BOLA            GET /api/notes/:id           (no ownership check)
//   broken-auth     GET /api/notes/:id           (no auth check)
//   mass-assign     POST /api/notes              (trusts client-supplied owner)
//   jwt-abuse       Authorization                (accepts alg=none + weak HS256 secret)
//   sqli            GET /api/search?q=…          (concatenates q into SQLite query)
//   cmdi            GET /api/ping?host=…         (passes host to system shell)
//   ssti            GET /api/greet?name=…        (renders name via text/template)
//   lfi             GET /api/file?path=…         (joins path into ReadFile call)
//   ssrf            GET /api/fetch?url=…         (server fetches arbitrary URL)
//   xss-reflected   GET /api/echo?msg=…          (writes msg into HTML response)
//   default-creds   POST /api/admin/login        (accepts admin:admin)
//   sensitive-files GET /.git/HEAD               (exposed git dir)
//   tech-fingerprint Server + X-Powered-By headers
//
// DO NOT DEPLOY. For local ngehe testing only.
package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	_ "modernc.org/sqlite"
)

const jwtSecret = "secret"

type note struct {
	ID      string `json:"id"`
	Owner   string `json:"owner"`
	Content string `json:"content"`
}

var notes = map[string]note{
	"1": {ID: "1", Owner: "alice", Content: "alice diary"},
	"2": {ID: "2", Owner: "alice", Content: "alice todos"},
	"3": {ID: "3", Owner: "bob", Content: "bob secrets"},
}

var db *sql.DB

func issueToken(sub string) string {
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": sub})
	s, _ := tok.SignedString([]byte(jwtSecret))
	return s
}

func userFromAuth(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Bearer ") {
		return ""
	}
	raw := strings.TrimPrefix(h, "Bearer ")
	parsed, err := jwt.Parse(raw, func(t *jwt.Token) (interface{}, error) {
		if t.Method.Alg() == "none" {
			return jwt.UnsafeAllowNoneSignatureType, nil
		}
		return []byte(jwtSecret), nil
	}, jwt.WithValidMethods([]string{"HS256", "none"}))
	if err != nil || !parsed.Valid {
		return ""
	}
	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return ""
	}
	if sub, ok := claims["sub"].(string); ok {
		return sub
	}
	return ""
}

func writeJSON(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("X-Powered-By", "ngehe-vuln-api/0.2 (Express-like)")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

var ssTIRe = regexp.MustCompile(`\{\{\s*(-?\d+)\s*\*\s*(-?\d+)\s*\}\}|\$\{\s*(-?\d+)\s*\*\s*(-?\d+)\s*\}|<%=\s*(-?\d+)\s*\*\s*(-?\d+)\s*%>|\{\s*(-?\d+)\s*\*\s*(-?\d+)\s*\}|#\{\s*(-?\d+)\s*\*\s*(-?\d+)\s*\}|@\(\s*(-?\d+)\s*\*\s*(-?\d+)\s*\)`)

func renderTemplate(s string) string {
	return ssTIRe.ReplaceAllStringFunc(s, func(m string) string {
		groups := ssTIRe.FindStringSubmatch(m)
		var a, b int
		for i := 1; i+1 < len(groups); i += 2 {
			if groups[i] != "" {
				a, _ = strconv.Atoi(groups[i])
				b, _ = strconv.Atoi(groups[i+1])
				break
			}
		}
		return strconv.Itoa(a * b)
	})
}

func writeHTML(w http.ResponseWriter, code int, html string) {
	w.Header().Set("X-Powered-By", "ngehe-vuln-api/0.2 (Express-like)")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(code)
	_, _ = io.WriteString(w, html)
}

func initDB() {
	var err error
	db, err = sql.Open("sqlite", ":memory:")
	if err != nil {
		panic(err)
	}
	// In-memory SQLite is per-connection — pin to one to keep the seeded table.
	db.SetMaxOpenConns(1)
	_, _ = db.Exec(`CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT, owner TEXT)`)
	_, _ = db.Exec(`INSERT INTO items (name, owner) VALUES ('apple','alice'),('banana','alice'),('cherry','bob')`)
}

func main() {
	initDB()

	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "vuln-api/0.2")
		w.Header().Set("X-Powered-By", "ngehe-vuln-api/0.2 (Express-like)")
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		writeHTML(w, 200, "<html><body><h1>vuln-api</h1><p>see <a href=/admin>/admin</a> or /api/*</p></body></html>")
	})

	mux.HandleFunc("/api/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]string{"status": "ok"})
	})

	mux.HandleFunc("/api/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, 405, map[string]string{"error": "method"})
			return
		}
		var body struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, 400, map[string]string{"error": "bad body"})
			return
		}
		switch body.Username + ":" + body.Password {
		case "alice:hunter2", "bob:swordfish":
			writeJSON(w, 200, map[string]string{"token": issueToken(body.Username)})
		default:
			writeJSON(w, 401, map[string]string{"error": "invalid creds"})
		}
	})

	// VULN — default credentials accepted on this admin endpoint.
	mux.HandleFunc("/api/admin/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, 405, map[string]string{"error": "method"})
			return
		}
		_ = r.ParseForm()
		var user, pass string
		ct := r.Header.Get("Content-Type")
		if strings.Contains(ct, "application/json") {
			var body struct{ Username, Password string }
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				writeJSON(w, 400, map[string]string{"error": "bad body"})
				return
			}
			user, pass = body.Username, body.Password
		} else {
			user = r.FormValue("username")
			pass = r.FormValue("password")
		}
		if user == "admin" && pass == "admin" {
			http.SetCookie(w, &http.Cookie{Name: "admin_session", Value: "yes-you-are", Path: "/"})
			writeJSON(w, 200, map[string]string{"message": "welcome admin"})
			return
		}
		writeJSON(w, 401, map[string]string{"error": "invalid"})
	})

	mux.HandleFunc("/api/me", func(w http.ResponseWriter, r *http.Request) {
		u := userFromAuth(r)
		if u == "" {
			writeJSON(w, 401, map[string]string{"error": "unauthorized"})
			return
		}
		writeJSON(w, 200, map[string]string{"user": u})
	})

	mux.HandleFunc("/api/notes", func(w http.ResponseWriter, r *http.Request) {
		u := userFromAuth(r)
		if u == "" {
			writeJSON(w, 401, map[string]string{"error": "unauthorized"})
			return
		}
		if r.Method == http.MethodPost {
			// VULN — trusts client-supplied owner field (mass-assign).
			var body note
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				writeJSON(w, 400, map[string]string{"error": "bad body"})
				return
			}
			if body.Owner == "" {
				body.Owner = u
			}
			body.ID = fmt.Sprintf("%d", len(notes)+1)
			notes[body.ID] = body
			writeJSON(w, 201, body)
			return
		}
		out := []note{}
		for _, n := range notes {
			if n.Owner == u {
				out = append(out, n)
			}
		}
		writeJSON(w, 200, out)
	})

	// VULN — no ownership check, no auth required (BOLA + broken auth).
	mux.HandleFunc("/api/notes/", func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/api/notes/")
		n, ok := notes[id]
		if !ok {
			writeJSON(w, 404, map[string]string{"error": "not found"})
			return
		}
		writeJSON(w, 200, n)
	})

	// VULN — SQL injection (string concat into SQLite query).
	mux.HandleFunc("/api/search", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		query := "SELECT id, name, owner FROM items WHERE name LIKE '%" + q + "%'"
		rows, err := db.Query(query)
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": "SQLite error: " + err.Error()})
			return
		}
		defer rows.Close()
		var out []map[string]interface{}
		for rows.Next() {
			var id int
			var name, owner string
			_ = rows.Scan(&id, &name, &owner)
			out = append(out, map[string]interface{}{"id": id, "name": name, "owner": owner})
		}
		writeJSON(w, 200, out)
	})

	// VULN — OS command injection (passes user input to shell).
	mux.HandleFunc("/api/ping", func(w http.ResponseWriter, r *http.Request) {
		host := r.URL.Query().Get("host")
		if host == "" {
			writeJSON(w, 400, map[string]string{"error": "host required"})
			return
		}
		cmd := exec.Command("sh", "-c", "echo pinging "+host)
		out, _ := cmd.CombinedOutput()
		writeJSON(w, 200, map[string]string{"output": string(out)})
	})

	// VULN — SSTI. Stand-in for Jinja2/Twig/Velocity: evaluates `{{expr}}` and
	// `${expr}` substitutions in user input. Supports integer arithmetic, the
	// minimum needed for ngehe's SSTI probe to confirm code evaluation.
	mux.HandleFunc("/api/greet", func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		rendered := renderTemplate("Hello " + name)
		writeJSON(w, 200, map[string]string{"greeting": rendered})
	})

	// VULN — LFI (joins user input into a file path).
	mux.HandleFunc("/api/file", func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Query().Get("path")
		if p == "" {
			writeJSON(w, 400, map[string]string{"error": "path required"})
			return
		}
		full := filepath.Join("/tmp/ngehe-vuln", p)
		b, err := os.ReadFile(full)
		if err != nil {
			writeJSON(w, 404, map[string]string{"error": err.Error()})
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		w.Write(b)
	})

	// VULN — SSRF (server fetches client-supplied URL).
	mux.HandleFunc("/api/fetch", func(w http.ResponseWriter, r *http.Request) {
		u := r.URL.Query().Get("url")
		if u == "" {
			writeJSON(w, 400, map[string]string{"error": "url required"})
			return
		}
		client := &http.Client{Timeout: 3 * time.Second}
		resp, err := client.Get(u)
		if err != nil {
			writeJSON(w, 502, map[string]string{"error": err.Error()})
			return
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		w.Header().Set("Content-Type", "text/plain")
		w.Write(body)
	})

	// VULN — reflected XSS (writes user input into HTML without escaping).
	mux.HandleFunc("/api/echo", func(w http.ResponseWriter, r *http.Request) {
		msg := r.URL.Query().Get("msg")
		writeHTML(w, 200, "<html><body><h1>Echo</h1><p>"+msg+"</p></body></html>")
	})

	// VULN — exposed .git/HEAD.
	mux.HandleFunc("/.git/HEAD", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "ref: refs/heads/main\n")
	})
	mux.HandleFunc("/.env", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "DATABASE_URL=postgres://ngehe:secret@localhost/app\nSECRET_KEY=super-secret-do-not-leak\n")
	})

	// Pretend admin endpoint, found via dir bruteforce.
	mux.HandleFunc("/admin", func(w http.ResponseWriter, r *http.Request) {
		writeHTML(w, 200, "<html><body><h1>Admin</h1><form action=/api/admin/login method=post><input name=username><input name=password type=password><button>login</button></form></body></html>")
	})

	addr := ":8787"
	// Ensure the LFI demo directory exists with a benign file.
	_ = os.MkdirAll("/tmp/ngehe-vuln", 0o755)
	_ = os.WriteFile("/tmp/ngehe-vuln/welcome.txt", []byte("ngehe vuln-api demo file\n"), 0o644)

	fmt.Println("vuln-api listening on", addr)
	_ = http.ListenAndServe(addr, mux)
}
