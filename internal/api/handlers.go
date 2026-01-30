// Package api implements REST API handlers for the coordinator.
package api

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/gorilla/websocket"

	"j5.nz/clustersh/internal/coordinator"
	"j5.nz/clustersh/internal/protocol"
)

// Server is the API server.
type Server struct {
	coord    *coordinator.Coordinator
	auth     *coordinator.AuthManager
	upgrader websocket.Upgrader
	mux      *http.ServeMux
}

// NewServer creates a new API server.
func NewServer(coord *coordinator.Coordinator, auth *coordinator.AuthManager) *Server {
	s := &Server{
		coord: coord,
		auth:  auth,
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool { return true },
		},
		mux: http.NewServeMux(),
	}
	s.registerRoutes()
	return s
}

func (s *Server) registerRoutes() {
	s.mux.HandleFunc("GET /machines", s.handleMachines)
	s.mux.HandleFunc("POST /run", s.handleRun)
	s.mux.HandleFunc("GET /output/{uuid}", s.handleOutput)
	s.mux.HandleFunc("GET /history/{machine}", s.handleHistory)
	s.mux.HandleFunc("POST /cancel/{uuid}", s.handleCancel)
	s.mux.HandleFunc("POST /login", s.handleLogin)
	s.mux.HandleFunc("POST /approve/{fingerprint}", s.handleApprove)
	s.mux.HandleFunc("GET /pending", s.handlePending)
	s.mux.HandleFunc("GET /install.sh", s.handleInstallSh)
	s.mux.HandleFunc("GET /install.ps1", s.handleInstallPs1)
	s.mux.HandleFunc("GET /install_client.sh", s.handleInstallClientSh)
	s.mux.HandleFunc("POST /agent/csr", s.handleAgentCSR)
	s.mux.HandleFunc("GET /ca.crt", s.handleCACert)
	s.mux.HandleFunc("GET /ws/agent", s.handleAgentWS)
}

// Handler returns the HTTP handler.
func (s *Server) Handler() http.Handler {
	return s.mux
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, protocol.APIError{Error: msg})
}

func (s *Server) handleMachines(w http.ResponseWriter, r *http.Request) {
	machines := s.coord.ListMachines()
	writeJSON(w, http.StatusOK, machines)
}

func (s *Server) handleRun(w http.ResponseWriter, r *http.Request) {
	var req protocol.RunRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Machine == "" {
		writeError(w, http.StatusBadRequest, "machine is required")
		return
	}
	if req.Command == "" {
		writeError(w, http.StatusBadRequest, "command is required")
		return
	}

	// Get client identity from TLS cert if available
	client := "unknown"
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		client = r.TLS.PeerCertificates[0].Subject.CommonName
	}

	jobID, err := s.coord.ExecuteCommand(r.Context(), client, &req)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, protocol.RunResponse{JobID: jobID})
}

func (s *Server) handleOutput(w http.ResponseWriter, r *http.Request) {
	uuid := r.PathValue("uuid")
	if uuid == "" {
		writeError(w, http.StatusBadRequest, "uuid is required")
		return
	}

	// Check for live output request
	live := r.URL.Query().Get("live") == "true"

	var output *protocol.JobOutput
	var err error

	if live {
		// Parse offset and limit
		var offset, limit int64
		if v := r.URL.Query().Get("offset"); v != "" {
			if _, parseErr := fmt.Sscanf(v, "%d", &offset); parseErr != nil {
				writeError(w, http.StatusBadRequest, "invalid offset")
				return
			}
		}
		if v := r.URL.Query().Get("limit"); v != "" {
			if _, parseErr := fmt.Sscanf(v, "%d", &limit); parseErr != nil {
				writeError(w, http.StatusBadRequest, "invalid limit")
				return
			}
		}

		output, err = s.coord.GetFullOutput(uuid, offset, limit)
	} else {
		output, err = s.coord.GetOutput(uuid)
	}

	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, output)
}

func (s *Server) handleHistory(w http.ResponseWriter, r *http.Request) {
	machine := r.PathValue("machine")
	if machine == "" {
		writeError(w, http.StatusBadRequest, "machine is required")
		return
	}

	history, err := s.coord.GetHistory(machine)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, history)
}

func (s *Server) handleCancel(w http.ResponseWriter, r *http.Request) {
	uuid := r.PathValue("uuid")
	if uuid == "" {
		writeError(w, http.StatusBadRequest, "uuid is required")
		return
	}

	client := "unknown"
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		client = r.TLS.PeerCertificates[0].Subject.CommonName
	}

	if err := s.coord.CancelCommand(client, uuid); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "cancelled"})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req protocol.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	cert, err := s.auth.RequestLogin(req.PublicKey, req.Fingerprint, req.Signature, req.Timestamp)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if cert != nil {
		writeJSON(w, http.StatusOK, protocol.LoginResponse{
			Status:      "approved",
			Certificate: *cert,
		})
	} else {
		writeJSON(w, http.StatusOK, protocol.LoginResponse{
			Status:  "pending",
			Message: "Login request submitted. Ask an administrator to approve your fingerprint.",
		})
	}
}

func (s *Server) handleApprove(w http.ResponseWriter, r *http.Request) {
	// Only allow from localhost
	if !isLocalRequest(r) {
		writeError(w, http.StatusForbidden, "approval only allowed from localhost")
		return
	}

	fingerprint := r.PathValue("fingerprint")
	if fingerprint == "" {
		writeError(w, http.StatusBadRequest, "fingerprint is required")
		return
	}

	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		req.Name = "client-" + fingerprint[:8]
	}

	if err := s.auth.Approve(fingerprint, req.Name); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "approved"})
}

func (s *Server) handlePending(w http.ResponseWriter, r *http.Request) {
	// Only allow from localhost
	if !isLocalRequest(r) {
		writeError(w, http.StatusForbidden, "only allowed from localhost")
		return
	}

	pending := s.auth.ListPending()
	writeJSON(w, http.StatusOK, pending)
}

func (s *Server) handleAgentCSR(w http.ResponseWriter, r *http.Request) {
	var req protocol.CSRRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	certPEM, err := s.auth.SignAgentCSR([]byte(req.CSR), req.MachineName)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, protocol.CSRResponse{
		Certificate: string(certPEM),
		CACert:      string(s.auth.GetCACert()),
	})
}

func (s *Server) handleCACert(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/x-pem-file")
	_, _ = w.Write(s.auth.GetCACert())
}

func (s *Server) handleAgentWS(w http.ResponseWriter, r *http.Request) {
	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade failed: %v", err)
		return
	}
	defer conn.Close()

	// Wait for registration message
	var msg protocol.Message
	if err := conn.ReadJSON(&msg); err != nil {
		log.Printf("Failed to read registration: %v", err)
		return
	}

	if msg.Type != protocol.MsgRegister {
		log.Printf("Expected register message, got: %s", msg.Type)
		return
	}

	var reg protocol.RegisterPayload
	if err := msg.DecodePayload(&reg); err != nil {
		log.Printf("Failed to decode registration: %v", err)
		return
	}

	agent, err := s.coord.RegisterAgent(conn, &reg)
	if err != nil {
		log.Printf("Failed to register agent: %v", err)
		return
	}
	defer s.coord.UnregisterAgent(agent.Name)

	// Read messages from agent
	for {
		var msg protocol.Message
		if err := conn.ReadJSON(&msg); err != nil {
			log.Printf("Agent %s read error: %v", agent.Name, err)
			break
		}

		if err := s.coord.HandleAgentMessage(agent.Name, &msg); err != nil {
			log.Printf("Agent %s message error: %v", agent.Name, err)
		}
	}
}

func isLocalRequest(r *http.Request) bool {
	host := r.Host
	if host == "localhost" || host == "127.0.0.1" || host == "[::1]" {
		return true
	}
	// Check X-Forwarded-For or RemoteAddr
	remoteAddr := r.RemoteAddr
	return remoteAddr == "127.0.0.1" || remoteAddr == "[::1]" ||
		remoteAddr == "localhost" || len(remoteAddr) > 0 && remoteAddr[0] == '/'
}
