package handlers

import (
	"context"
	"net/http"
	"os"

	"github.com/hanxi/gamepass-local/internal/models"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

type AdminHandler struct {
	userCol *mongo.Collection
}

func NewAdminHandler(db *mongo.Database) *AdminHandler {
	return &AdminHandler{
		userCol: db.Collection("users"),
	}
}

func (h *AdminHandler) GetUsers(c *gin.Context) {
	var users []models.User
	cursor, err := h.userCol.Find(context.TODO(), bson.M{})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to query users"})
		return
	}
	if err = cursor.All(context.TODO(), &users); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to decode users"})
		return
	}
	c.JSON(http.StatusOK, users)
}

func (h *AdminHandler) Login(c *gin.Context) {
	var input models.User
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if input.Username == os.Getenv("ADMIN_USER") && input.Password == os.Getenv("ADMIN_PASS") {
		session := sessions.Default(c)
		session.Set("admin", true)
		session.Save()
		c.JSON(http.StatusOK, gin.H{"message": "admin login success"})
		return
	}
	c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid admin credentials"})
}
