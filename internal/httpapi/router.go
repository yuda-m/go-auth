package httpapi

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"

	"go-auth/internal/config"
	"go-auth/internal/httpapi/handler"
	"go-auth/internal/httpapi/middleware"
	"go-auth/internal/model"
	"go-auth/internal/service"
)

func NewRouter(cfg *config.Config, authSvc *service.AuthService, tokenSvc *service.TokenService) *gin.Engine {
	if cfg.Env == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	r := gin.New()
	r.Use(gin.Logger(), gin.Recovery())

	authHandler := handler.NewAuthHandler(authSvc)
	userHandler := handler.NewUserHandler(authSvc.Store())

	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status": "ok",
			"env":    cfg.Env,
		})
	})

	auth := r.Group("/auth")
	{
		auth.POST("/register", authHandler.Register)
		auth.POST("/login", authHandler.Login)
		auth.POST("/refresh", authHandler.Refresh)
		auth.POST("/logout", authHandler.Logout)
	}

	protected := r.Group("/")
	protected.Use(middleware.RequireAuth(tokenSvc))
	{
		protected.GET("/me", userHandler.Me)
		protected.GET("/admin/overview", middleware.RequireRole(model.RoleAdmin), userHandler.AdminOverview)
	}

	r.NoRoute(func(c *gin.Context) {
		c.JSON(http.StatusNotFound, gin.H{
			"success": false,
			"error":   fmt.Sprintf("route %s not found", c.Request.URL.Path),
		})
	})

	return r
}
