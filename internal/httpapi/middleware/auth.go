package middleware

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"go-auth/internal/model"
	"go-auth/internal/service"
)

const claimsKey = "auth_claims"

func RequireAuth(tokenSvc *service.TokenService) gin.HandlerFunc {
	return func(c *gin.Context) {
		accessToken, err := bearerToken(c.GetHeader("Authorization"))
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"success": false, "error": "missing bearer token"})
			return
		}

		claims, err := tokenSvc.ParseAndValidate(accessToken, "access")
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"success": false, "error": "invalid access token"})
			return
		}

		c.Set(claimsKey, claims)
		c.Next()
	}
}

func RequireRole(role model.Role) gin.HandlerFunc {
	return func(c *gin.Context) {
		raw, exists := c.Get(claimsKey)
		if !exists {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"success": false, "error": "unauthorized"})
			return
		}

		claims, ok := raw.(*service.Claims)
		if !ok || claims.Role != role {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"success": false, "error": "forbidden"})
			return
		}

		c.Next()
	}
}

func CurrentClaims(c *gin.Context) (*service.Claims, bool) {
	raw, exists := c.Get(claimsKey)
	if !exists {
		return nil, false
	}

	claims, ok := raw.(*service.Claims)
	return claims, ok
}

func bearerToken(header string) (string, error) {
	if header == "" {
		return "", errors.New("missing authorization header")
	}

	parts := strings.Fields(header)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", errors.New("invalid authorization header")
	}

	return parts[1], nil
}
