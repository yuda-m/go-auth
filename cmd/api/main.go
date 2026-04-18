package main

import (
	"log"

	"go-auth/internal/config"
	httpapi "go-auth/internal/httpapi"
	"go-auth/internal/repository/memory"
	"go-auth/internal/service"
)

func main() {
	cfg := config.Load()

	store := memory.NewStore()
	tokenSvc := service.NewTokenService(cfg.JWTSecret, cfg.AccessTokenTTL, cfg.RefreshTokenTTL)
	authSvc := service.NewAuthService(store, tokenSvc)

	if err := authSvc.SeedAdmin(cfg.AdminEmail, cfg.AdminPassword); err != nil {
		log.Fatalf("seed admin: %v", err)
	}

	router := httpapi.NewRouter(cfg, authSvc, tokenSvc)

	log.Printf("auth service listening on %s", cfg.Port)
	if err := router.Run(":" + cfg.Port); err != nil {
		log.Fatalf("server stopped: %v", err)
	}
}
