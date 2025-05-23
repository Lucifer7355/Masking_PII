package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
)

// Unified error response
func WriteJSONError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(ErrorResponse{Error: message})
}

// /mask handler
func MaskHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var req MaskRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteJSONError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}
	res, ok := ApplyMask(req.Type, req.Value)
	if !ok {
		WriteJSONError(w, http.StatusBadRequest, "Invalid value for the specified type")
		return
	}
	_ = json.NewEncoder(w).Encode(MaskResponse{Masked: res})
}

// /bulk handler
func BulkHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

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
	_ = json.NewEncoder(w).Encode(resp)
}

// /validate handler
func ValidateHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var req MaskRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteJSONError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}
	_, ok := ApplyMask(req.Type, req.Value)
	_ = json.NewEncoder(w).Encode(ValidationResponse{Valid: ok})
}

// /detect handler
func DetectHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var req DetectionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteJSONError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}
	typeDetected := DetectType(req.Value)
	if typeDetected == "" {
		_ = json.NewEncoder(w).Encode(map[string]string{})
		return
	}
	_ = json.NewEncoder(w).Encode(DetectionResponse{Type: typeDetected})
}

// /generate-key handler
func GenerateAPIKeyHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	key, err := GenerateAPIKey()
	if err != nil {
		WriteJSONError(w, http.StatusInternalServerError, "Could not generate API key")
		return
	}

	err = redisClient.Set(ctx, "apikey:"+key, true, 0).Err()
	if err != nil {
		WriteJSONError(w, http.StatusInternalServerError, "Failed to store API key")
		return
	}

	_ = json.NewEncoder(w).Encode(APIKeyResponse{Key: key})
}

// helper: generates 32-char API key
func GenerateAPIKey() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
