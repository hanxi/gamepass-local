package main

import (
	"embed"
	"fmt"
	"log"
	"os"

	"project/internal/db"
	"project/internal/routes"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/mongo/mongodriver"
	"github.com/gin-contrib/static"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

//go:embed public
var embeddedFiles embed.FS

func main() {
	_ = godotenv.Load()
	db.InitMongo()

	store := mongodriver.NewStore(
		db.DB.Collection("sessions"),
		3600,
		true,
		[]byte(os.Getenv("SESSION_SECRET")),
	)
	r := gin.Default()
	r.Use(sessions.Sessions("mysession", store))

	// 前端静态资源
	fs, err := static.EmbedFolder(embeddedFiles, "public")
	if err != nil {
		panic(err)
	}
	r.Use(static.Serve("/", fs))

	// 设置路由
	routes.SetupRoutes(r, db.DB)

	// 启动服务器
	port := os.Getenv("PORT")
	addr := fmt.Sprintf(":%s", port)
	if err := r.Run(addr); err != nil {
		log.Fatal(err)
	}
}
