package routes

import (
	"project/internal/handlers"
	"project/internal/middleware"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/mongo"
)

func SetupRoutes(r *gin.Engine, db *mongo.Database) {
	// 创建处理器
	authHandler := handlers.NewAuthHandler(db)
	adminHandler := handlers.NewAdminHandler(db)

	// API 路由组
	api := r.Group("/api")

	// 认证相关路由
	auth := api.Group("/auth")
	{
		auth.POST("/register", authHandler.Register)
		auth.POST("/login", authHandler.Login)
		auth.POST("/logout", authHandler.Logout)
	}

	// 管理员相关路由
	admin := api.Group("/admin")
	{
		// 管理员登录接口 - 不需要权限验证
		admin.POST("/login", adminHandler.Login)

		// 需要管理员权限的路由组
		adminProtected := admin.Group("")
		adminProtected.Use(middleware.AdminRequired())
		{
			adminProtected.GET("/users", adminHandler.GetUsers)
			// 其他需要管理员权限的路由...
		}

	}
}
