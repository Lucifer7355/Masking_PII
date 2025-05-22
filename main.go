package main

import (
	"context"
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

var (
	ctx         = context.Background()
	redisClient *redis.Client
)

// Load Redis from REDIS_URL
func initRedis() {
	opt, err := redis.ParseURL(os.Getenv("REDIS_URL"))
	if err != nil {
		log.Fatalf("❌ Failed to parse Redis URL: %v", err)
	}
	redisClient = redis.NewClient(opt)

	_, err = redisClient.Ping(ctx).Result()
	if err != nil {
		log.Fatalf("❌ Redis connection failed: %v", err)
	}
	log.Println("✅ Connected to Redis")
}

// Lua script for token bucket rate limiting
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
end
`

// Middleware to rate limit per IP
func redisRateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			http.Error(w, "Unable to parse IP address", http.StatusInternalServerError)
			return
		}

		key := "ratelimit:" + ip
		maxTokens := 3
		refillTime := 1 // seconds
		now := time.Now().Unix()

		result, err := redisClient.Eval(ctx, luaScript, []string{key},
			maxTokens, refillTime, now).Result()
		if err != nil {
			http.Error(w, "Internal error", http.StatusInternalServerError)
			log.Printf("Redis error: %v", err)
			return
		}

		if result.(int64) == 0 {
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// Mask PAN
func maskPAN(pan string) (string, bool) {
	matched, _ := regexp.MatchString(`^[A-Z]{5}[0-9]{4}[A-Z]$`, pan)
	if matched {
		return pan[:2] + "XXX" + pan[5:], true
	}
	return "", false
}

// Mask Aadhaar
func maskAadhaar(aadhaar string) (string, bool) {
	digits := strings.ReplaceAll(strings.ReplaceAll(aadhaar, "-", ""), " ", "")
	matched, _ := regexp.MatchString(`^[0-9]{12}$`, digits)
	if matched {
		return "XXXX-XXXX-" + digits[8:], true
	}
	return "", false
}

// Main handler
func maskHandler(w http.ResponseWriter, r *http.Request) {
	var req MaskRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	var masked string
	var ok bool

	switch strings.ToLower(req.Type) {
	case "pan":
		masked, ok = maskPAN(req.Value)
	case "aadhaar":
		masked, ok = maskAadhaar(req.Value)
	default:
		http.Error(w, "Invalid type. Must be 'pan' or 'aadhaar'", http.StatusBadRequest)
		return
	}

	if !ok {
		http.Error(w, "Invalid value for the specified type", http.StatusBadRequest)
		return
	}

	response := MaskResponse{Masked: masked}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Main entrypoint
func main() {
	err := godotenv.Load()
	if err != nil {
		log.Println("⚠️  No .env file found, using Railway env")
	}
	initRedis()

	mux := http.NewServeMux()
	mux.HandleFunc("/mask", maskHandler)

	log.Println("🚀 Masking API running on http://localhost:8080/mask")
	err = http.ListenAndServe(":8080", redisRateLimitMiddleware(mux))
	if err != nil {
		log.Fatal("❌ Server failed:", err)
	}
}
