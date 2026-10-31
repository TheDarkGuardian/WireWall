package control

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/TheDarkGuardian/WireWall/internal/model"
	"github.com/TheDarkGuardian/WireWall/internal/policy"
)

type session struct {
	csrf    string
	expires time.Time
}
type attempt struct {
	count int
	reset time.Time
}
type HTTPServer struct {
	service  *Service
	token    [32]byte
	sessions map[string]session
	attempts map[string]attempt
	mu       sync.Mutex
	webDir   string
	remote   http.Handler
}

func NewHTTP(service *Service, token, webDir string) *HTTPServer {
	return &HTTPServer{service: service, token: sha256.Sum256([]byte(token)), sessions: map[string]session{}, attempts: map[string]attempt{}, webDir: webDir}
}
func (h *HTTPServer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/health", func(w http.ResponseWriter, r *http.Request) {
		if h.remote != nil {
			h.remote.ServeHTTP(w, r)
			return
		}
		respond(w, 200, map[string]any{"ok": true, "backend": h.service.backend, "version": "0.1.0"})
	})
	mux.HandleFunc("GET /api/v1/session", h.sessionGet)
	mux.HandleFunc("POST /api/v1/session", h.sessionCreate)
	mux.HandleFunc("DELETE /api/v1/session", h.auth(h.sessionDelete))
	if h.remote != nil {
		mux.HandleFunc("/api/v1/", h.auth(h.proxyAPI))
	} else {
		mux.HandleFunc("GET /api/v1/snapshot", h.auth(func(w http.ResponseWriter, r *http.Request) { respond(w, 200, h.service.Snapshot()) }))
		mux.HandleFunc("GET /api/v1/stream", h.auth(h.stream))
		mux.HandleFunc("GET /api/v1/policy", h.auth(func(w http.ResponseWriter, r *http.Request) { respond(w, 200, h.service.Policy()) }))
		mux.HandleFunc("POST /api/v1/policy/validate", h.auth(h.policyValidate))
		mux.HandleFunc("PUT /api/v1/policy", h.auth(h.policyApply))
		mux.HandleFunc("POST /api/v1/policy/confirm", h.auth(func(w http.ResponseWriter, r *http.Request) {
			if err := h.service.ConfirmActivation(); err != nil {
				fail(w, 409, err)
				return
			}
			respond(w, 200, map[string]bool{"ok": true})
		}))
		mux.HandleFunc("POST /api/v1/bans", h.auth(h.banAdd))
		mux.HandleFunc("DELETE /api/v1/bans/{id}", h.auth(h.banDelete))
		mux.HandleFunc("POST /api/v1/lab/scenarios", h.auth(h.scenario))
		mux.HandleFunc("POST /api/v1/lab/reset", h.auth(func(w http.ResponseWriter, r *http.Request) {
			if err := h.service.Reset(); err != nil {
				fail(w, 409, err)
				return
			}
			respond(w, 200, map[string]bool{"ok": true})
		}))
		mux.HandleFunc("GET /api/v1/audit", h.auth(h.audit))
		mux.HandleFunc("GET /api/v1/events", h.auth(h.eventHistory))
		mux.HandleFunc("GET /api/v1/events/export", h.auth(h.eventHistoryExport))
	}
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) { fail(w, 404, errors.New("API yolu bulunamadı")) })
	mux.HandleFunc("/", h.static)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'")
		if !validOrigin(r) {
			fail(w, 403, errors.New("Origin doğrulaması başarısız"))
			return
		}
		mux.ServeHTTP(w, r)
	})
}
func validOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if err != nil || u.Scheme != scheme || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.ForceQuery {
		return false
	}
	return strings.EqualFold(u.Host, r.Host)
}
func (h *HTTPServer) validToken(token string) bool {
	got := sha256.Sum256([]byte(token))
	return subtle.ConstantTimeCompare(got[:], h.token[:]) == 1
}
func (h *HTTPServer) getSession(r *http.Request) (session, bool) {
	cookie, err := r.Cookie("wirewall_session")
	if err != nil {
		return session{}, false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	s, ok := h.sessions[cookie.Value]
	if !ok || time.Now().After(s.expires) {
		delete(h.sessions, cookie.Value)
		return session{}, false
	}
	return s, true
}
func (h *HTTPServer) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authorization := r.Header.Get("Authorization")
		if strings.HasPrefix(authorization, "Bearer ") && h.validToken(strings.TrimPrefix(authorization, "Bearer ")) {
			next(w, r)
			return
		}
		s, ok := h.getSession(r)
		if !ok {
			fail(w, 401, errors.New("oturum gerekli"))
			return
		}
		if r.Method != "GET" && r.Method != "HEAD" && subtle.ConstantTimeCompare([]byte(r.Header.Get("X-WireWall-CSRF")), []byte(s.csrf)) != 1 {
			fail(w, 403, errors.New("CSRF doğrulaması başarısız"))
			return
		}
		next(w, r)
	}
}
func (h *HTTPServer) sessionGet(w http.ResponseWriter, r *http.Request) {
	s, ok := h.getSession(r)
	respond(w, 200, map[string]any{"authenticated": ok, "csrfToken": s.csrf})
}
func (h *HTTPServer) sessionCreate(w http.ResponseWriter, r *http.Request) {
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	h.mu.Lock()
	now := time.Now()
	a := h.attempts[host]
	if now.After(a.reset) {
		a = attempt{reset: now.Add(time.Minute)}
	}
	if a.count >= 10 {
		h.mu.Unlock()
		fail(w, 429, errors.New("çok fazla deneme; bir dakika bekleyin"))
		return
	}
	a.count++
	if len(h.attempts) < 1024 || h.attempts[host].count > 0 {
		h.attempts[host] = a
	}
	h.mu.Unlock()
	var input struct {
		Token string `json:"token"`
	}
	if err := decode(w, r, &input); err != nil {
		fail(w, 400, err)
		return
	}
	if !h.validToken(input.Token) {
		fail(w, 401, errors.New("geçersiz operatör anahtarı"))
		return
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		fail(w, 500, err)
		return
	}
	id := hex.EncodeToString(raw)
	csrf := newID()
	h.mu.Lock()
	for key, s := range h.sessions {
		if now.After(s.expires) {
			delete(h.sessions, key)
		}
	}
	if len(h.sessions) >= 128 {
		h.mu.Unlock()
		fail(w, 503, errors.New("oturum kapasitesi dolu"))
		return
	}
	h.sessions[id] = session{csrf: csrf, expires: now.Add(8 * time.Hour)}
	h.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "wirewall_session", Value: id, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: r.TLS != nil, MaxAge: 8 * 60 * 60})
	respond(w, 200, map[string]any{"authenticated": true, "csrfToken": csrf})
}
func (h *HTTPServer) sessionDelete(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie("wirewall_session"); err == nil {
		h.mu.Lock()
		delete(h.sessions, c.Value)
		h.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: "wirewall_session", Value: "", Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: -1})
	respond(w, 200, map[string]bool{"ok": true})
}
func (h *HTTPServer) policyValidate(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Policy model.Policy `json:"policy"`
	}
	if err := decode(w, r, &in); err != nil {
		fail(w, 400, err)
		return
	}
	if err := policy.Validate(in.Policy); err != nil {
		fail(w, 422, err)
		return
	}
	respond(w, 200, map[string]bool{"valid": true})
}
func (h *HTTPServer) policyApply(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Policy          model.Policy `json:"policy"`
		ExpectedVersion uint64       `json:"expectedVersion"`
	}
	if err := decode(w, r, &in); err != nil {
		fail(w, 400, err)
		return
	}
	p, err := h.service.ApplyPolicy(in.Policy, in.ExpectedVersion)
	if err != nil {
		code := 422
		if errors.Is(err, ErrConflict) {
			code = 409
		}
		fail(w, code, err)
		return
	}
	respond(w, 200, p)
}
func (h *HTTPServer) banAdd(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Address         string `json:"address"`
		Reason          string `json:"reason"`
		DurationSeconds int    `json:"durationSeconds"`
	}
	if err := decode(w, r, &in); err != nil {
		fail(w, 400, err)
		return
	}
	b, err := h.service.AddBan(in.Address, in.Reason, in.DurationSeconds)
	if err != nil {
		fail(w, 422, err)
		return
	}
	respond(w, 201, b)
}
func (h *HTTPServer) banDelete(w http.ResponseWriter, r *http.Request) {
	err := h.service.DeleteBan(r.PathValue("id"))
	if err != nil {
		code := 422
		if errors.Is(err, os.ErrNotExist) {
			code = 404
		}
		fail(w, code, err)
		return
	}
	respond(w, 200, map[string]bool{"ok": true})
}
func (h *HTTPServer) scenario(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Scenario string `json:"scenario"`
	}
	if err := decode(w, r, &in); err != nil {
		fail(w, 400, err)
		return
	}
	if err := h.service.SetScenario(in.Scenario); err != nil {
		fail(w, 409, err)
		return
	}
	respond(w, 200, map[string]string{"scenario": in.Scenario})
}
func (h *HTTPServer) audit(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	items, err := h.service.store.Audit(limit)
	if err != nil {
		fail(w, 500, err)
		return
	}
	respond(w, 200, map[string]any{"items": items})
}
func (h *HTTPServer) stream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		fail(w, 500, errors.New("stream desteklenmiyor"))
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("X-Accel-Buffering", "no")
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(10 * time.Second))
		data, err := json.Marshal(h.service.Snapshot())
		if err != nil {
			return
		}
		if _, err = io.WriteString(w, "event: snapshot\ndata: "+string(data)+"\n\n"); err != nil {
			return
		}
		flusher.Flush()
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			if _, ok := h.getSession(r); !ok && !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
				return
			}
		}
	}
}
func (h *HTTPServer) static(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" && r.Method != "HEAD" {
		fail(w, 405, errors.New("yöntem desteklenmiyor"))
		return
	}
	path := filepath.Join(h.webDir, filepath.Clean("/"+r.URL.Path))
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			path = filepath.Join(h.webDir, "index.html")
		} else {
			fail(w, 500, errors.New("statik dosya okunamadı"))
			return
		}
	}
	if _, err := os.Stat(path); err != nil {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(503)
		_, _ = io.WriteString(w, "WireWall API hazır. Web panelini derleyin: cd web && npm ci && npm run build\n")
		return
	}
	http.ServeFile(w, r, path)
}
func decode(w http.ResponseWriter, r *http.Request, target any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(target); err != nil {
		return errors.New("geçersiz JSON: " + err.Error())
	}
	if err := d.Decode(&struct{}{}); err != io.EOF {
		return errors.New("tek JSON nesnesi gerekli")
	}
	return nil
}
func respond(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func fail(w http.ResponseWriter, status int, err error) {
	respond(w, status, map[string]string{"error": err.Error()})
}
