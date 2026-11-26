package handlers

import (
	"context"
	"errors"
	nethttp "net/http"

	"github.com/boson-chat/auth/internal/services/bridge"
)

// BridgeService is the evrd bridge's accounts (internal/services/bridge).
type BridgeService interface {
	Reconcile(ctx context.Context) (bridge.Result, error)
	Status(ctx context.Context) (bridge.Status, error)
}

// registerBridge mounts the bridge's internal endpoints (only with BRIDGE_API_URL set).
func (h *Handlers) registerBridge(mux *nethttp.ServeMux) {
	if h.Bridge == nil {
		return
	}
	mux.HandleFunc("GET /internal/v1/bridge/status", h.internalOnly(h.internalBridgeStatus))
	mux.HandleFunc("POST /internal/v1/bridge/reconcile", h.internalOnly(h.internalBridgeReconcile))
}

// internalBridgeStatus: GET /internal/v1/bridge/status, the outbox (pending
// and failing changes, the last error) and the last full sync.
func (h *Handlers) internalBridgeStatus(w nethttp.ResponseWriter, r *nethttp.Request) {
	st, err := h.Bridge.Status(r.Context())
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, nethttp.StatusOK, st)
}

// internalBridgeReconcile: POST /internal/v1/bridge/reconcile runs a full
// sync now and says what it did (409 reconcile_running while another runs).
func (h *Handlers) internalBridgeReconcile(w nethttp.ResponseWriter, r *nethttp.Request) {
	res, err := h.Bridge.Reconcile(r.Context())
	if errors.Is(err, bridge.ErrReconcileRunning) {
		writeError(w, r, err)
		return
	}
	out, status := map[string]any{"ok": err == nil, "result": res}, nethttp.StatusOK
	if err != nil {
		// The bridge (or the database) failed part of it: what's done stays done.
		out["error"], status = err.Error(), nethttp.StatusBadGateway
	}
	writeJSON(w, status, out)
}
