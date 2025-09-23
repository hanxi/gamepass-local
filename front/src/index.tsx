import { serve } from "bun";
import index from "./index.html";

// 从 .env 读取 API 地址，提供默认值以防缺失
const API_TARGET = process.env.API_TARGET || "http://localhost:3001";

const server = serve({
  routes: {
    "/api/*": async (req) => {
      try {
        const url = new URL(req.url);
        const targetUrl = new URL(url.pathname, API_TARGET);
        targetUrl.search = url.search;

        console.log(`Proxying request to: ${targetUrl.toString()}`);

        const response = await fetch(targetUrl, {
          method: req.method,
          headers: req.headers,
          body: req.body
        });

        return new Response(response.body, {
          status: response.status,
          headers: response.headers
        });
      } catch (error) {
        console.error('Proxy error:', error);
        return new Response(JSON.stringify({
          error: "Proxy Error",
          message: error.message
        }), {
          status: 500,
          headers: { "Content-Type": "application/json" }
        });
      }
    },

    "/*": index,
  },

  host: "0.0.0.0",
  port: process.env.PORT || 3000,
  development: process.env.NODE_ENV !== "production",
});

console.log(`🚀 Server running at ${server.url}`);
console.log(`📦 API proxy target: ${API_TARGET}`);
