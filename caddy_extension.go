package caddypreauth

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/gobwas/glob"
)

func init() {
	caddy.RegisterModule(PathAuth{})
}

// PathAuth is a Caddy module for encrypted path-based authentication
type PathAuth struct {
	Key string `json:"key"` // Symmetric key (base64-encoded)
}

// CaddyModule returns the Caddy module information
func (PathAuth) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.path_auth",
		New: func() caddy.Module { return new(PathAuth) },
	}
}

// Provision sets up the module
func (p *PathAuth) Provision(ctx caddy.Context) error {
	if p.Key == "" {
		return fmt.Errorf("symmetric key is required")
	}
	return nil
}

// ServeHTTP implements the caddyhttp.MiddlewareHandler interface
func (p PathAuth) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	// Get the Authorization header
	auth := r.Header.Get("Authorization")
	if auth == "" || len(auth) < 6 || auth[:6] != "Basic " {
		w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
		return caddyhttp.Error(http.StatusUnauthorized, nil)
	}

	// Decode the base64-encoded credentials
	creds, err := base64.StdEncoding.DecodeString(auth[6:])
	if err != nil {
		return caddyhttp.Error(http.StatusUnauthorized, fmt.Errorf("invalid base64: %v", err))
	}

	// Split into username and password
	parts := string(creds)
	colonIdx := -1
	for i, c := range parts {
		if c == ':' {
			colonIdx = i
			break
		}
	}
	if colonIdx == -1 {
		return caddyhttp.Error(http.StatusUnauthorized, fmt.Errorf("invalid credentials format"))
	}
	username := parts[:colonIdx]
	password := parts[colonIdx+1:]

	// Check if username is "preauth"
	if username != "preauth" {
		return caddyhttp.Error(http.StatusUnauthorized, fmt.Errorf("invalid username"))
	}

	// Decode the symmetric key
	key, err := base64.StdEncoding.DecodeString(p.Key)
	if err != nil {
		return caddyhttp.Error(http.StatusInternalServerError, fmt.Errorf("invalid key: %v", err))
	}

	// Decrypt the password
	payload, err := decryptPayload(password, key)
	if err != nil {
		return caddyhttp.Error(http.StatusUnauthorized, fmt.Errorf("decryption failed: %v", err))
	}

	// Check expiration
	if time.Now().Unix() > payload.Exp {
		return caddyhttp.Error(http.StatusUnauthorized, fmt.Errorf("token expired"))
	}

	// Match the requested path against the allowed glob
	g, err := glob.Compile(payload.Path)
	if err != nil {
		return caddyhttp.Error(http.StatusInternalServerError, fmt.Errorf("invalid glob: %v", err))
	}
	if !g.Match(r.URL.Path) {
		return caddyhttp.Error(http.StatusForbidden, fmt.Errorf("path not allowed"))
	}

	// All checks passed, proceed with the request
	return next.ServeHTTP(w, r)
}

type Payload struct {
	Path string `json:"path"`
	Exp  int64  `json:"exp"`
}

func decryptPayload(encrypted string, key []byte) (Payload, error) {
	// Base64-decode the encrypted payload
	ciphertext, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return Payload{}, fmt.Errorf("invalid base64: %v", err)
	}

	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return Payload{}, fmt.Errorf("cipher creation failed: %v", err)
	}

	// Use AES-GCM
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return Payload{}, fmt.Errorf("GCM creation failed: %v", err)
	}

	// Extract nonce and ciphertext
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return Payload{}, fmt.Errorf("ciphertext too short")
	}
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	// Decrypt
	data, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return Payload{}, fmt.Errorf("decryption failed: %v", err)
	}

	// Unmarshal JSON payload
	var payload Payload
	if err := json.Unmarshal(data, &payload); err != nil {
		return Payload{}, fmt.Errorf("invalid payload: %v", err)
	}

	return payload, nil
}

// UnmarshalCaddyfile parses the Caddyfile configuration.
func (p *PathAuth) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if d.NextArg() {
			switch d.Val() {
			case "key":
				if !d.NextArg() {
					return d.ArgErr()
				}
				p.Key = d.Val()
			default:
				return d.Errf("unrecognized subdirective: %s", d.Val())
			}
		}
	}
	return nil
}

// Interface guards to ensure compliance
var (
	_ caddy.Provisioner           = (*PathAuth)(nil)
	_ caddyhttp.MiddlewareHandler = (*PathAuth)(nil)
	_ caddyfile.Unmarshaler       = (*PathAuth)(nil)
)

// Register the module with Caddy
func init() {
	caddy.RegisterModule(PathAuth{})
	httpcaddyfile.RegisterHandlerDirective("path_auth", func(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
		var p PathAuth
		err := p.UnmarshalCaddyfile(h.Dispenser)
		return &p, err
	})
}
