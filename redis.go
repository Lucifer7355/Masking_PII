package main

import (
	"context"
	"log"
	"os"

	"github.com/go-redis/redis/v8"
)

var (
	ctx         = context.Background()
	redisClient *redis.Client
)

func InitRedis() {
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
