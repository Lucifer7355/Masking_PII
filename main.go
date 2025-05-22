package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/joho/godotenv"
)

type MaskRequest struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type MaskResponse struct {
	Masked string `json:"masked"`
}

type BulkRequest []MaskRequest

type BulkResponse []MaskResponse

type ValidationResponse struct {
	Valid bool `json:"valid"`
}

type DetectionRequest struct {
	Value string `json:"value"`
}

type DetectionResponse struct {
	Type string `json:"type,omitempty"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}

type APIKeyResponse struct {
	Key string `json:"key"`
}

var (
	ctx         = context.Background()
	redisClient *redis.Client
)

func initRedis() {
	opt, err := redis.ParseURL(os.Getenv("REDIS_URL"))
	if err != nil {
		log.Fatalf("Failed to parse Redis URL: %v", err)
	}
	redisClient = redis.NewClient(opt)
	if _, err := redisClient.Ping(ctx).Result(); err != nil {
		log.Fatalf("Redis connection failed: %v", err)
	}
	log.Println("Connected to Redis")
}

func writeJSONError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(ErrorResponse{Error: message})
}

const luaScript = `
local key = KEYS[1]
local max_tokens = tonumber(ARGV[1])
local refill_time = tonumber(ARGV[2])
local current_time = tonumber(ARGV[3])
local bucket = redis.call("HMGET", key, "tokens", "last_refill")
local tokens = tonumber(bucket[1]) or max_tokens
local last_refill = tonumber(bucket[2]) or 0
local delta = math.max(0, current_time - last_refill)
local refill = math.floor(delta / refill_time)
tokens = math.min(max_tokens, tokens + refill)
if tokens > 0 then
	tokens = tokens - 1
	redis.call("HMSET", key, "tokens", tokens, "last_refill", current_time)
	redis.call("EXPIRE", key, refill_time * 2)
	return 1
else
	return 0
end`

func redisRateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "Unable to parse IP address")
			return
		}
		key := "ratelimit:" + ip
		maxTokens := 3
		refillTime := 1
		now := time.Now().Unix()
		result, err := redisClient.Eval(ctx, luaScript, []string{key}, maxTokens, refillTime, now).Result()
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "Internal error")
			return
		}
		if result.(int64) == 0 {
			writeJSONError(w, http.StatusTooManyRequests, "Too Many Requests")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func requireAPIKeyMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.Header.Get("X-API-Key")
		if key == "" {
			writeJSONError(w, http.StatusUnauthorized, "Missing API key")
			return
		}
		exists, err := redisClient.Exists(ctx, "apikey:"+key).Result()
		if err != nil || exists == 0 {
			writeJSONError(w, http.StatusUnauthorized, "Invalid API key")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func generateAPIKeyHandler(w http.ResponseWriter, r *http.Request) {
	key, err := generateAPIKey()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "Could not generate API key")
		return
	}

	err = redisClient.Set(ctx, "apikey:"+key, true, 0).Err()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "Failed to store API key")
		return
	}

	w.Header().Set("Content-Type", "application/json") // ✅ Add this line
	json.NewEncoder(w).Encode(APIKeyResponse{Key: key})
}

func generateAPIKey() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// Masking logic
func maskPAN(pan string) (string, bool) {
	matched, _ := regexp.MatchString(`^[A-Z]{5}[0-9]{4}[A-Z]$`, pan)
	if matched {
		return pan[:2] + "XXX" + pan[5:], true
	}
	return "", false
}

func maskAadhaar(aadhaar string) (string, bool) {
	digits := strings.ReplaceAll(strings.ReplaceAll(aadhaar, "-", ""), " ", "")
	matched, _ := regexp.MatchString(`^[0-9]{12}$`, digits)
	if matched {
		return "XXXX-XXXX-" + digits[8:], true
	}
	return "", false
}

func maskPhone(phone string) (string, bool) {
	digits := strings.ReplaceAll(phone, " ", "")
	matched, _ := regexp.MatchString(`^[6-9][0-9]{9}$`, digits)
	if matched {
		return digits[:2] + "*****" + digits[7:], true
	}
	return "", false
}

func maskEmail(email string) (string, bool) {
	parts := strings.Split(email, "@")
	if len(parts) != 2 || len(parts[0]) < 2 {
		return "", false
	}
	return string(parts[0][0]) + "***@" + parts[1], true
}

func maskGSTIN(gstin string) (string, bool) {
	matched, _ := regexp.MatchString(`^[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z]{1}[1-9A-Z]{1}Z[0-9A-Z]{1}$`, gstin)
	if matched {
		return gstin[:5] + "*****" + gstin[10:], true
	}
	return "", false
}

func detectType(value string) string {
	if _, ok := maskPAN(value); ok {
		return "pan"
	}
	if _, ok := maskAadhaar(value); ok {
		return "aadhaar"
	}
	if _, ok := maskPhone(value); ok {
		return "phone"
	}
	if _, ok := maskEmail(value); ok {
		return "email"
	}
	if _, ok := maskGSTIN(value); ok {
		return "gstin"
	}
	return ""
}

func maskHandler(w http.ResponseWriter, r *http.Request) {
	var req MaskRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}
	res, ok := applyMask(req.Type, req.Value)
	if !ok {
		writeJSONError(w, http.StatusBadRequest, "Invalid value for the specified type")
		return
	}
	json.NewEncoder(w).Encode(MaskResponse{Masked: res})
}

func applyMask(t, v string) (string, bool) {
	switch strings.ToLower(t) {
	case "pan":
		return maskPAN(v)
	case "aadhaar":
		return maskAadhaar(v)
	case "phone":
		return maskPhone(v)
	case "email":
		return maskEmail(v)
	case "gstin":
		return maskGSTIN(v)
	default:
		return "", false
	}
}

func bulkHandler(w http.ResponseWriter, r *http.Request) {
	var reqs BulkRequest
	if err := json.NewDecoder(r.Body).Decode(&reqs); err != nil {
		writeJSONError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}
	var resp BulkResponse
	for _, req := range reqs {
		masked, _ := applyMask(req.Type, req.Value)
		resp = append(resp, MaskResponse{Masked: masked})
	}
	json.NewEncoder(w).Encode(resp)
}

func validateHandler(w http.ResponseWriter, r *http.Request) {
	var req MaskRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}
	_, ok := applyMask(req.Type, req.Value)
	json.NewEncoder(w).Encode(ValidationResponse{Valid: ok})
}

func detectHandler(w http.ResponseWriter, r *http.Request) {
	var req DetectionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}
	typeDetected := detectType(req.Value)
	if typeDetected == "" {
		json.NewEncoder(w).Encode(struct{}{})
		return
	}
	json.NewEncoder(w).Encode(DetectionResponse{Type: typeDetected})
}

func main() {
	_ = godotenv.Load()
	initRedis()

	mux := http.NewServeMux()
	mux.HandleFunc("/mask", maskHandler)
	mux.HandleFunc("/bulk", bulkHandler)
	mux.HandleFunc("/validate", validateHandler)
	mux.HandleFunc("/detect", detectHandler)
	mux.HandleFunc("/generate-key", generateAPIKeyHandler)

	log.Println("Masking API running on :8080")
	if err := http.ListenAndServe(":8080", redisRateLimitMiddleware(mux)); err != nil {
		log.Fatal("Server failed:", err)
	}
}
