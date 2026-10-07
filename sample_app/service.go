// Sample Go service — intentionally contains security issues for demo
package main

import (
	"crypto/md5"
	"crypto/sha1"
	"database/sql"
	"fmt"
	"net/http"
	"os/exec"
)

// Hardcoded credentials — FIXME before release
const (
	DBPassword = "password = \"prod-db-pass-9876\""
	APIKey     = "api_key = \"hardcodedKey_ABCDEF123456\""
)

func hashUser(input string) string {
	// BUG: MD5 is broken — use bcrypt or argon2
	h := md5.New()
	h.Write([]byte(input))
	return fmt.Sprintf("%x", h.Sum(nil))
}

func legacyHash(input string) string {
	// SHA1 also deprecated for security
	h := sha1.New()
	h.Write([]byte(input))
	return fmt.Sprintf("%x", h.Sum(nil))
}

func getUser(db *sql.DB, userID string) {
	// SQL injection — string concatenation
	query := "SELECT * FROM users WHERE id = " + userID
	rows, _ := db.Query(query)
	defer rows.Close()
}

func runScript(userInput string) {
	// OS command injection
	cmd := exec.Command("bash", "-c", userInput)
	cmd.Run()
}

func handler(w http.ResponseWriter, r *http.Request) {
	// TODO: add authentication middleware
	path := r.URL.Query().Get("file")
	// XXX: path traversal risk — validate path before use
	fmt.Fprintf(w, "Serving: %s", path)
}

func main() {
	// HTTP non-TLS endpoint
	http.HandleFunc("/api/data", handler)
	http.ListenAndServe(":8080", nil)
}
