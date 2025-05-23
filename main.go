package main

import (
	"log"
	"net/http"

	"github.com/joho/godotenv"
)

func main() {
	_ = godotenv.Load()
	InitRedis()

	mux := http.NewServeMux()
	// mux.Handle("/mask", RequireAPIKeyMiddleware(http.HandlerFunc(MaskHandler)))
	// mux.Handle("/bulk", RequireAPIKeyMiddleware(http.HandlerFunc(BulkHandler)))
	// mux.Handle("/validate", RequireAPIKeyMiddleware(http.HandlerFunc(ValidateHandler)))
	// mux.HandleFunc("/rotate-key", RotateAPIKeyHandler)
	// mux.HandleFunc("/usage", UsageHandler)
	// mux.HandleFunc("/metadata", MetadataHandler)
	// mux.HandleFunc("/revoke-key", RevokeAPIKeyHandler)
	// mux.Handle("/detect", RequireAPIKeyMiddleware(http.HandlerFunc(DetectHandler)))
	// mux.HandleFunc("/generate-key", GenerateAPIKeyHandler)

	mux.Handle("/mask", RequireAPIKeyMiddleware(http.HandlerFunc(MaskHandler)))
	mux.Handle("/bulk", RequireAPIKeyMiddleware(http.HandlerFunc(BulkHandler)))
	mux.Handle("/validate", RequireAPIKeyMiddleware(http.HandlerFunc(ValidateHandler)))
	mux.Handle("/detect", RequireAPIKeyMiddleware(http.HandlerFunc(DetectHandler)))
	mux.Handle("/usage", RequireAPIKeyMiddleware(http.HandlerFunc(UsageHandler)))       // if enabled
	mux.Handle("/metadata", RequireAPIKeyMiddleware(http.HandlerFunc(MetadataHandler))) // if enabled

	log.Println("Masking API running on :8080")
	log.Fatal(http.ListenAndServe(":8080", RedisRateLimitMiddleware(mux)))
}
