package main

import (
	"log"
	"net/http"
)

func main() {
	http.HandleFunc("/health", PingHandler)
	http.HandleFunc("/mask", MaskHandler)
	http.HandleFunc("/bulk", BulkHandler)
	http.HandleFunc("/validate", ValidateHandler)
	http.HandleFunc("/detect", DetectHandler)

	log.Println("Server started on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
