package main

import (
	"encoding/json"
	"net/http"
	"time"
)

func WriteJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func WriteJSONError(w http.ResponseWriter, status int, message string) {
	WriteJSON(w, status, ErrorResponse{Error: message})
}

func PingHandler(w http.ResponseWriter, r *http.Request) {
	WriteJSON(w, http.StatusOK, map[string]string{
		"status":  "ok",
		"message": "PII Masking API is live",
		"time":    time.Now().Format(time.RFC3339),
	})
}

func MaskHandler(w http.ResponseWriter, r *http.Request) {
	var req MaskRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteJSONError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}
	masked, ok := ApplyMask(req.Type, req.Value)
	if !ok {
		WriteJSONError(w, http.StatusBadRequest, "Invalid value for the specified type")
		return
	}
	WriteJSON(w, http.StatusOK, MaskResponse{Masked: masked})
}

func BulkHandler(w http.ResponseWriter, r *http.Request) {
	var reqs BulkRequest
	if err := json.NewDecoder(r.Body).Decode(&reqs); err != nil {
		WriteJSONError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}
	var resp BulkResponse
	for _, req := range reqs {
		masked, _ := ApplyMask(req.Type, req.Value)
		resp = append(resp, MaskResponse{Masked: masked})
	}
	WriteJSON(w, http.StatusOK, resp)
}

func ValidateHandler(w http.ResponseWriter, r *http.Request) {
	var req MaskRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteJSONError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}
	_, ok := ApplyMask(req.Type, req.Value)
	WriteJSON(w, http.StatusOK, ValidationResponse{Valid: ok})
}

func DetectHandler(w http.ResponseWriter, r *http.Request) {
	var req DetectionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteJSONError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}
	detected := DetectType(req.Value)
	if detected == "" {
		WriteJSON(w, http.StatusOK, map[string]string{}) // empty JSON object
		return
	}
	WriteJSON(w, http.StatusOK, DetectionResponse{Type: detected})
}
