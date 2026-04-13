# oidc-authkit

通用 Python OIDC 认证包，为 Python Web 应用提供与 Authelia OIDC Provider 的统一集成。

## 功能特性

- 基于 Authelia OIDC 的登录 / 回调 / 登出
- 当前用户识别 (`current_user`)
- 本地用户自动映射 (find or create)
- 登录保护装饰器 / 依赖注入
- Group 权限检查
- 可匿名访问支持
- 支持 FastAPI 和 Flask
- Cookie-based 签名会话
- 可扩展架构（自定义 UserStore、SessionStore、OIDCClient）

## 安装

```bash
# FastAPI 支持
pip install oidc-authkit[fastapi]

# Flask 支持
pip install oidc-authkit[flask]

# 全部可选依赖
pip install oidc-authkit[all]
```

## 快速开始

### FastAPI

```python
from fastapi import FastAPI, Request
from oidc_authkit.adapters.fastapi import FastAPIAuth, register_exception_handlers

app = FastAPI()

auth = FastAPIAuth(
    issuer="https://auth.example.com",
    client_id="myapp",
    client_secret="YOUR_SECRET",
    base_url="https://myapp.example.com",
    secret_key="your-session-secret-key-at-least-16-chars",
)

auth.init_app(app)
register_exception_handlers(app)

# 公开页面
@app.get("/")
async def index(request: Request):
    user = await auth.current_user(request)
    return {"authenticated": user.is_authenticated}

# 需要登录
@app.get("/profile")
async def profile(user=auth.require_user()):
    return {"name": user.local_user.display_name}

# 需要特定 group
@app.get("/admin")
async def admin(user=auth.require_group("admins")):
    return {"message": "Welcome, admin!"}
```

### Flask

```python
from flask import Flask
from oidc_authkit.adapters.flask import FlaskAuth

app = Flask(__name__)

auth = FlaskAuth(
    issuer="https://auth.example.com",
    client_id="myapp",
    client_secret="YOUR_SECRET",
    base_url="https://myapp.example.com",
    secret_key="your-session-secret-key-at-least-16-chars",
)

auth.init_app(app)

# 公开页面
@app.route("/")
def index():
    user = auth.current_user()
    return {"authenticated": user.is_authenticated}

# 需要登录
@app.route("/profile")
@auth.login_required()
def profile():
    user = auth.current_user()
    return {"name": user.local_user.display_name}

# 需要特定 group
@app.route("/admin")
@auth.require_group("admins")
def admin():
    user = auth.current_user()
    return {"message": "Welcome, admin!"}
```

## Authelia Client 配置要求

在 Authelia 中为您的应用注册 OIDC client：

```yaml
identity_providers:
  oidc:
    clients:
      - client_id: myapp
        client_secret: 'YOUR_HASHED_SECRET'
        token_endpoint_auth_method: client_secret_basic
        authorization_policy: two_factor
        redirect_uris:
          - https://myapp.example.com/oidc/callback
        scopes:
          - openid
          - profile
          - email
          - groups
```

**重要**：`redirect_uris` 必须与 `base_url + callback_path` 完全一致。

## 获取用户名（username / preferred_username）

**Authelia 默认只在 ID token 里返回 `sub`（UUID），不包含 `preferred_username`。**
如果你需要在 `UserStore.create_from_identity` 中拿到用户名（例如按用户名匹配已有账号），必须开启 `auto_fetch_userinfo=True`，让 oidc_authkit 在 callback 阶段额外请求 userinfo endpoint，并将 `preferred_username` 等字段合并到 `identity.claims` 中。

```python
auth = FastAPIAuth(
    issuer="...",
    client_id="...",
    client_secret="...",
    base_url="...",
    secret_key="...",
    auto_fetch_userinfo=True,   # 必须开启，否则 identity.username 为 None
)
```

开启后，`identity.username`（即 `identity.claims.preferred_username`）将包含 Authelia 用户名，可直接用于数据库匹配：

```python
async def create_from_identity(self, identity: ExternalIdentity) -> LocalUser:
    username = identity.username  # 开启 auto_fetch_userinfo 后有值
    user = db.query(User).filter(User.username == username).first()
    ...
```

如果不开启 `auto_fetch_userinfo`，`identity.claims.raw` 里只有 `sub`（UUID 格式），无法匹配业务系统的用户名。

---

## 配置说明

### 核心配置

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `issuer` | OIDC Provider URL | 必填 |
| `client_id` | OIDC Client ID | 必填 |
| `client_secret` | OIDC Client Secret | 必填 |
| `base_url` | 应用外部访问 URL | 必填 |
| `secret_key` | Session 签名密钥 (≥16字符) | 必填 |
| `auto_fetch_userinfo` | 登录回调时额外请求 userinfo endpoint，将 `preferred_username`、`email`、`name` 合并到 claims | `False` |
| `callback_path` | 回调路径 | `/oidc/callback` |
| `login_path` | 登录路径 | `/oidc/login` |
| `logout_path` | 登出路径 | `/oidc/logout` |
| `scopes` | OIDC scopes | `["openid", "profile", "email", "groups"]` |
| `token_endpoint_auth_method` | Token 端点客户端认证方式，可选 `client_secret_basic` 或 `client_secret_post` | `client_secret_basic` |
| `allow_anonymous` | 是否允许匿名 | `True` |

### Session / Cookie 配置

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `cookie_name` | Cookie 名称 | `oidc_authkit_session` |
| `cookie_secure` | Secure 标志 | `True` |
| `cookie_http_only` | HttpOnly 标志 | `True` |
| `same_site` | SameSite 策略 | `lax` |
| `max_age_seconds` | Session 最大存活时间 | `86400` (24h) |

### 本地用户映射

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `create_user_if_missing` | 自动创建本地用户 | `True` |
| `update_profile_on_login` | 登录时更新 profile | `True` |
| `username_claim` | 用户名来源 claim | `preferred_username` |
| `email_claim` | 邮箱来源 claim | `email` |
| `display_name_claim` | 显示名来源 claim | `name` |
| `groups_claim` | 组来源 claim | `groups` |

## 自定义 UserStore

实现 `UserStore` 协议，替换默认的 `InMemoryUserStore`：

```python
from oidc_authkit.domain.interfaces import UserStore
from oidc_authkit.domain.models import ExternalIdentity, LocalUser

class MyDatabaseUserStore:
    async def get_by_external_identity(self, issuer: str, subject: str) -> LocalUser | None:
        # 查询你的数据库
        ...

    async def create_from_identity(self, identity: ExternalIdentity) -> LocalUser:
        # 创建用户记录
        ...

    async def update_from_identity(self, user: LocalUser, identity: ExternalIdentity) -> LocalUser:
        # 更新用户记录
        ...

    async def get_by_id(self, user_id: str | int) -> LocalUser | None:
        # 按 ID 查询
        ...

# 在初始化时传入
auth = FastAPIAuth(
    ...,
    user_store=MyDatabaseUserStore(),
)
```

## 常见错误排查

### "Invalid auth configuration"
检查配置项是否完整，特别是 `base_url` 和 `issuer` 是否为有效 URL，`secret_key` 是否足够长。

### "OIDC state parameter mismatch"
- 检查 cookie 设置是否正常（`SameSite`, `Secure` 等）
- 检查浏览器是否阻止了第三方 cookie
- 确认 callback URL 与 Authelia 配置一致

### "Failed to fetch OIDC discovery document"
确认 `issuer` URL 可达，OIDC Discovery endpoint 正常。

### 登录成功但 `identity.username` 为 None，导致 DB INSERT 失败或匹配到错误账号
Authelia 默认不在 ID token 中包含 `preferred_username`，需要开启 `auto_fetch_userinfo=True`。详见[获取用户名](#获取用户名username--preferred_username)章节。

### 登录后没有回到原页面
检查 `return_to` 参数是否为安全的同站路径。外部 URL 会被拒绝以防止 open redirect。

## 架构概览

```
oidc_authkit/
├── config/          # 配置模型和校验
├── domain/          # 领域模型、错误、接口
├── protocol/        # OIDC 协议处理（state, nonce, claims）
├── application/     # 应用服务层（登录、回调、当前用户）
├── infrastructure/  # 基础设施（OIDC client, session, user store）
├── adapters/        # 框架适配器（FastAPI, Flask）
├── permissions/     # 权限检查
└── hooks/           # 生命周期事件钩子
```

## 开发

```bash
# 安装开发依赖
pip install -e ".[dev,all]"

# 运行测试
pytest

# 类型检查
mypy oidc_authkit

# 代码格式化
ruff check oidc_authkit tests
```

## License

MIT
