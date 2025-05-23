package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
)

func WriteJSONError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(ErrorResponse{Error: message})
}

func MaskHandler(w http.ResponseWriter, r *http.Request) {
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
	json.NewEncoder(w).Encode(MaskResponse{Masked: res})
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
	json.NewEncoder(w).Encode(resp)
}

func ValidateHandler(w http.ResponseWriter, r *http.Request) {
	var req MaskRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteJSONError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}
	_, ok := ApplyMask(req.Type, req.Value)
	json.NewEncoder(w).Encode(ValidationResponse{Valid: ok})
}

func DetectHandler(w http.ResponseWriter, r *http.Request) {
	var req DetectionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteJSONError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}
	typeDetected := DetectType(req.Value)
	if typeDetected == "" {
		json.NewEncoder(w).Encode(struct{}{})
		return
	}
	json.NewEncoder(w).Encode(DetectionResponse{Type: typeDetected})
}

func GenerateAPIKeyHandler(w http.ResponseWriter, r *http.Request) {
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

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(APIKeyResponse{Key: key})
}

func GenerateAPIKey() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
