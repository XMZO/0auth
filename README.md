# 0auth

单密码反向代理鉴权。

- 未登录时返回内置登录页
- 支持中英双语
- 支持 `none` / `pow` / `turnstile` / `pow+turnstile`
- 支持失败次数封禁
- 支持有状态会话与会话轮换
- 可用 `docker compose` 直接部署

## 用法

1. 复制 `.env.example` 为 `.env`
2. 至少修改这几项：

```env
LISTEN_ADDR=127.0.0.1:8088
TARGET_URL=http://127.0.0.1:5003

AUTH_PASSWORD=change-me
SESSION_SECRET=replace-with-a-long-random-secret

LOGIN_CHALLENGE_MODE=pow
```

3. 启动：

```bash
docker compose up -d
```

文件会话默认会写到：

```text
./data/auth-sessions.json
```

运行中同目录下可能还会出现：

```text
./data/auth-sessions.json.wal
```

这是增量更新用的 sidecar 文件，后续会自动压缩回主文件。

## 端口说明

如果你的原项目已经占用：

```yaml
ports:
  - 127.0.0.1:5003:5003
```

那么 0auth 推荐这样配：

```env
LISTEN_ADDR=127.0.0.1:8088
TARGET_URL=http://127.0.0.1:5003
```

然后让外层反代或浏览器访问 `127.0.0.1:8088`。

不要让 0auth 和原项目同时监听同一个宿主机端口。

## 镜像

默认 `docker-compose.yml` 使用：

```text
ghcr.io/xmzo/0auth:latest
```

支持：

- `linux/amd64`
- `linux/arm64`
- `linux/arm/v7`

## 配置

常用配置都在 `.env.example`。

如果要启用 Turnstile，至少再补这几项：

```env
LOGIN_CHALLENGE_MODE=turnstile
TURNSTILE_SITE_KEY=your-site-key
TURNSTILE_SECRET_KEY=your-secret-key
```

如果要和 PoW 叠加：

```env
LOGIN_CHALLENGE_MODE=pow+turnstile
```

## file 模式路径

- 容器内路径：`/var/lib/0auth/auth-sessions.json`
- 宿主机路径：`./data/auth-sessions.json`
