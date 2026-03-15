# 0auth

单密码反向代理鉴权。

- 未登录时返回内置登录页
- 支持中英双语
- 支持 PoW
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
```

3. 启动：

```bash
docker compose up -d
```

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
