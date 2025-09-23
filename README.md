# Gin + MongoDB + React 用户注册/登录系统

## 项目结构
```
.
├── main.go          # Gin 后端入口
├── go.mod           # Go 模块定义
├── public/          # React 构建后的静态文件 (go:embed 嵌入)
├── front/           # React + Bun + Tailwind 前端工程
└── README.md        # 使用说明
```

## 后端运行

1. 启动 MongoDB，确保地址为 `mongodb://localhost:27017`
2. 修改 `.env` 文件配置管理员账户：
   ```env
   ADMIN_USER=admin
   ADMIN_PASS=123456
   SESSION_SECRET=secret
   ```
3. 安装依赖并运行：
   ```bash
   go mod tidy
   go run main.go
   ```

服务将运行在 `http://localhost:8080`

## 前端运行

前端使用 [Bun](https://bun.sh/) + React + TailwindCSS

1. 安装依赖：
   ```bash
   cd front
   bun install
   ```
2. 开发模式运行：
   ```bash
   bun run dev
   ```
   默认运行在 `http://localhost:3000`
3. 构建前端：
   ```bash
   bun run build
   ```
   构建结果会输出到 `../public` 目录，Go 会通过 `go:embed` 自动嵌入。

## 管理后台

访问 `http://localhost:8080/admin` 使用 `.env` 中的管理员账户登录，查看用户列表。
