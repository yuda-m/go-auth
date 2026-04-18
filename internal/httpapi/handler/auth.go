package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"go-auth/internal/service"
)

type AuthHandler struct {
	service *service.AuthService
}

func NewAuthHandler(service *service.AuthService) *AuthHandler {
	return &AuthHandler{service: service}
}

func (h *AuthHandler) Register(c *gin.Context) {
	var input service.RegisterInput
	if err := c.ShouldBindJSON(&input); err != nil {
		respondFail(c, http.StatusBadRequest, err.Error())
		return
	}

	user, pair, err := h.service.Register(input)
	if err != nil {
		status := http.StatusInternalServerError
		switch err {
		case service.ErrUserAlreadyExists:
			status = http.StatusConflict
		}
		respondFail(c, status, err.Error())
		return
	}

	respondOK(c, http.StatusCreated, gin.H{
		"user":   user,
		"tokens": pair,
	})
}

func (h *AuthHandler) Login(c *gin.Context) {
	var input service.LoginInput
	if err := c.ShouldBindJSON(&input); err != nil {
		respondFail(c, http.StatusBadRequest, err.Error())
		return
	}

	user, pair, err := h.service.Login(input)
	if err != nil {
		respondFail(c, http.StatusUnauthorized, err.Error())
		return
	}

	respondOK(c, http.StatusOK, gin.H{
		"user":   user,
		"tokens": pair,
	})
}

func (h *AuthHandler) Refresh(c *gin.Context) {
	var input struct {
		RefreshToken string `json:"refresh_token" binding:"required"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		respondFail(c, http.StatusBadRequest, err.Error())
		return
	}

	user, pair, err := h.service.Refresh(input.RefreshToken)
	if err != nil {
		respondFail(c, http.StatusUnauthorized, err.Error())
		return
	}

	respondOK(c, http.StatusOK, gin.H{
		"user":   user,
		"tokens": pair,
	})
}

func (h *AuthHandler) Logout(c *gin.Context) {
	var input struct {
		RefreshToken string `json:"refresh_token" binding:"required"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		respondFail(c, http.StatusBadRequest, err.Error())
		return
	}

	if err := h.service.Logout(input.RefreshToken); err != nil {
		respondFail(c, http.StatusUnauthorized, err.Error())
		return
	}

	respondOK(c, http.StatusOK, gin.H{
		"message": "logged out",
	})
}
