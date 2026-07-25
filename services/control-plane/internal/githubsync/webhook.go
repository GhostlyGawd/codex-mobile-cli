package githubsync

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strings"
)

type OwnerResolver func(context.Context) (string, error)

type Webhook struct {
	secret []byte
	syncer *Syncer
	owner  OwnerResolver
}

func NewWebhook(secret []byte, syncer *Syncer, owner OwnerResolver) (*Webhook, error) {
	if len(secret) < 32 || syncer == nil || owner == nil {
		return nil, errors.New("GitHub webhook secret, syncer, and owner resolver are required")
	}
	return &Webhook{secret: append([]byte(nil), secret...), syncer: syncer, owner: owner}, nil
}

func (h *Webhook) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || !deliveryPattern.MatchString(r.Header.Get("X-GitHub-Delivery")) {
		http.Error(w, "invalid webhook request", http.StatusBadRequest)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil || !h.validSignature(body, r.Header.Get("X-Hub-Signature-256")) {
		http.Error(w, "invalid webhook signature", http.StatusUnauthorized)
		return
	}
	event := r.Header.Get("X-GitHub-Event")
	if event == "ping" {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if event != "installation" && event != "installation_repositories" {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	var payload struct {
		Action       string `json:"action"`
		Installation struct {
			ID int64 `json:"id"`
		} `json:"installation"`
	}
	// GitHub payloads contain many event-specific fields. Decode through a
	// narrow raw envelope instead of rejecting those documented additions.
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(body, &envelope); err != nil {
		http.Error(w, "invalid webhook payload", http.StatusBadRequest)
		return
	}
	if err := json.Unmarshal(envelope["action"], &payload.Action); err != nil || errString(payload.Action) {
		http.Error(w, "invalid webhook payload", http.StatusBadRequest)
		return
	}
	if err := json.Unmarshal(envelope["installation"], &payload.Installation); err != nil || payload.Installation.ID <= 0 {
		http.Error(w, "invalid webhook payload", http.StatusBadRequest)
		return
	}
	ownerID, err := h.owner(r.Context())
	if err != nil || ownerID == "" {
		http.Error(w, "owner enrollment required", http.StatusConflict)
		return
	}
	if event == "installation" {
		switch payload.Action {
		case "deleted", "suspend":
			err = h.syncer.Suspend(r.Context(), ownerID, payload.Installation.ID)
		case "unsuspend":
			_, err = h.syncer.SyncProviderUnsuspend(r.Context(), ownerID, payload.Installation.ID)
		default:
			_, err = h.syncer.Sync(r.Context(), ownerID, payload.Installation.ID)
		}
	} else {
		_, err = h.syncer.Sync(r.Context(), ownerID, payload.Installation.ID)
	}
	if err != nil {
		http.Error(w, "GitHub synchronization failed", http.StatusBadGateway)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

func (h *Webhook) validSignature(body []byte, value string) bool {
	if !strings.HasPrefix(value, "sha256=") || len(value) != len("sha256=")+sha256.Size*2 {
		return false
	}
	presented, err := hex.DecodeString(strings.TrimPrefix(value, "sha256="))
	if err != nil {
		return false
	}
	digest := hmac.New(sha256.New, h.secret)
	_, _ = digest.Write(body)
	return subtle.ConstantTimeCompare(presented, digest.Sum(nil)) == 1
}

func errString(value string) bool {
	return value == "" || len(value) > 64 || strings.ContainsAny(value, "\x00\r\n")
}

var deliveryPattern = regexp.MustCompile(`^[A-Za-z0-9-]{1,128}$`)
