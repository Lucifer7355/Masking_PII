package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"
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

	plan := r.Header.Get("X-Plan-Level")
	if plan != "pro" && plan != "ultra" {
		WriteJSONError(w, http.StatusForbidden, "Bulk masking is available only for Pro or Ultra plans")
		return
	}

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

	// Allow ?plan=pro for admin (optional)
	plan := "free"
	if r.URL.Query().Get("plan") == "pro" && r.Header.Get("X-Admin-Token") == "secret-123" {
		plan = "pro"
	} else if r.URL.Query().Get("plan") == "ultra" && r.Header.Get("X-Admin-Token") == "secret-123" {
		plan = "ultra"
	}

	data := map[string]interface{}{
		"active":     "true",
		"plan":       plan,
		"created_at": time.Now().Format(time.RFC3339),
	}

	pipe := redisClient.TxPipeline()
	pipe.HSet(ctx, "apikey:"+key, data)
	pipe.Expire(ctx, "apikey:"+key, 30*24*time.Hour)
	_, err = pipe.Exec(ctx)

	if err != nil {
		WriteJSONError(w, http.StatusInternalServerError, "Failed to store API key")
		return
	}

	json.NewEncoder(w).Encode(APIKeyResponse{Key: key})
}

// helper: generates 32-char API key
func GenerateAPIKey() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func RotateAPIKeyHandler(w http.ResponseWriter, r *http.Request) {
	oldKey := r.Header.Get("X-API-Key")
	if oldKey == "" {
		WriteJSONError(w, http.StatusBadRequest, "Old API key missing")
		return
	}

	meta, err := redisClient.HGetAll(ctx, "apikey:"+oldKey).Result()
	if err != nil || meta["active"] != "true" {
		WriteJSONError(w, http.StatusUnauthorized, "Old key invalid or revoked")
		return
	}

	newKey, err := GenerateAPIKey()
	if err != nil {
		WriteJSONError(w, http.StatusInternalServerError, "Failed to generate new key")
		return
	}

	pipe := redisClient.TxPipeline()
	pipe.HSet(ctx, "apikey:"+newKey, meta)
	pipe.Expire(ctx, "apikey:"+newKey, 30*24*time.Hour)
	pipe.HSet(ctx, "apikey:"+oldKey, "active", "false") // revoke old key
	_, err = pipe.Exec(ctx)

	if err != nil {
		WriteJSONError(w, http.StatusInternalServerError, "Key rotation failed")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(APIKeyResponse{Key: newKey})
}

func UsageHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	key := r.Header.Get("X-API-Key")
	if key == "" {
		WriteJSONError(w, http.StatusUnauthorized, "Missing API key")
		return
	}

	// Validate if key is active
	meta, err := redisClient.HGetAll(ctx, "apikey:"+key).Result()
	if err != nil || meta["active"] != "true" {
		WriteJSONError(w, http.StatusUnauthorized, "Invalid or revoked API key")
		return
	}

	// Get usage count
	count, err := redisClient.Get(ctx, "apikey:"+key+":usage_count").Int64()
	if err != nil {
		count = 0
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"key":         key,
		"usage_count": count,
		"plan":        meta["plan"],
		"created_at":  meta["created_at"],
		"active":      meta["active"],
		"expires_in":  redisClient.TTL(ctx, "apikey:"+key).Val().String(),
	})
}

func MetadataHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	key := r.Header.Get("X-API-Key")
	if key == "" {
		WriteJSONError(w, http.StatusUnauthorized, "Missing API key")
		return
	}

	meta, err := redisClient.HGetAll(ctx, "apikey:"+key).Result()
	if err != nil || len(meta) == 0 {
		WriteJSONError(w, http.StatusUnauthorized, "Invalid API key")
		return
	}

	meta["expires_in"] = redisClient.TTL(ctx, "apikey:"+key).Val().String()
	json.NewEncoder(w).Encode(meta)
}

func RevokeAPIKeyHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	key := r.Header.Get("X-API-Key")
	if key == "" {
		WriteJSONError(w, http.StatusUnauthorized, "Missing API key")
		return
	}

	meta, err := redisClient.HGetAll(ctx, "apikey:"+key).Result()
	if err != nil || len(meta) == 0 {
		WriteJSONError(w, http.StatusUnauthorized, "Invalid API key")
		return
	}

	// Mark as inactive
	err = redisClient.HSet(ctx, "apikey:"+key, "active", "false").Err()
	if err != nil {
		WriteJSONError(w, http.StatusInternalServerError, "Failed to revoke key")
		return
	}

	json.NewEncoder(w).Encode(map[string]string{
		"message": "API key revoked successfully",
	})
}
