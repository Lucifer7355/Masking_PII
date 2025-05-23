package main

import (
	"net"
	"net/http"
	"time"
)

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

func RedisRateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			WriteJSONError(w, http.StatusInternalServerError, "Unable to parse IP address")
			return
		}
		key := "ratelimit:" + ip
		maxTokens := 3
		refillTime := 1
		now := time.Now().Unix()

		result, err := redisClient.Eval(ctx, luaScript, []string{key}, maxTokens, refillTime, now).Result()
		if err != nil || result.(int64) == 0 {
			WriteJSONError(w, http.StatusTooManyRequests, "Too Many Requests")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func RequireAPIKeyMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.Header.Get("X-API-Key")
		if key == "" || redisClient.Exists(ctx, "apikey:"+key).Val() == 0 {
			WriteJSONError(w, http.StatusUnauthorized, "Invalid API key")
			return
		}
		next.ServeHTTP(w, r)
	})
}
