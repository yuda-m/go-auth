package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"go-auth/internal/httpapi/middleware"
	"go-auth/internal/model"
	"go-auth/internal/repository/memory"
)

type UserHandler struct {
	store *memory.Store
}

func NewUserHandler(store *memory.Store) *UserHandler {
	return &UserHandler{store: store}
}

func (h *UserHandler) Me(c *gin.Context) {
	claims, hasClaims := middleware.CurrentClaims(c)
	if !hasClaims {
		respondFail(c, http.StatusUnauthorized, "unauthorized")
		return
	}

	user, err := h.store.GetUserByID(claims.UserID)
	if err != nil {
		respondFail(c, http.StatusNotFound, "user not found")
		return
	}

	respondOK(c, http.StatusOK, gin.H{
		"user": user,
	})
}

func (h *UserHandler) AdminOverview(c *gin.Context) {
	claims, hasClaims := middleware.CurrentClaims(c)
	if !hasClaims {
		respondFail(c, http.StatusUnauthorized, "unauthorized")
		return
	}

	respondOK(c, http.StatusOK, gin.H{
		"message": "admin-only access granted",
		"role":    model.RoleAdmin,
		"user_id": claims.UserID,
	})
}
