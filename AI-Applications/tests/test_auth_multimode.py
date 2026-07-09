"""测试多模式认证：Cookie / API Key / JWT 组合认证"""
import json
import time
import pytest
from fastapi.testclient import TestClient


def test_auth_modes_endpoint():
    """测试 /api/v1/auth/modes 返回正确的模式状态。"""
    from llamafw.app import app
    client = TestClient(app)
    response = client.get("/api/v1/auth/modes")
    assert response.status_code == 200
    data = response.json()
    assert "modes" in data
    assert "cookie" in data["modes"]
    assert "apikey" in data["modes"]
    assert "jwt" in data["modes"]
    assert "active_modes" in data
    assert data["active_modes"] >= 1
    print("[OK] auth/modes endpoint works")


def test_health_includes_auth_info():
    """测试 health 端点包含多模式认证信息。"""
    from llamafw.app import app
    client = TestClient(app)
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert "auth_modes" in data
    print("[OK] health endpoint includes auth_modes info")


def test_jwt_create_and_verify():
    """测试 JWT 创建和验证函数。"""
    from llamafw.app import _create_jwt, _verify_jwt

    secret = "test-secret-123"
    payload = {"sub": "admin", "role": "admin", "iat": int(time.time()), "exp": int(time.time()) + 3600}
    token = _create_jwt(payload, secret, "HS256")

    # Token 应为三段式
    parts = token.split(".")
    assert len(parts) == 3
    print(f"[OK] JWT created with 3 parts, length={len(token)}")

    # 验证应成功
    verified = _verify_jwt(token, secret)
    assert verified["sub"] == "admin"
    assert verified["role"] == "admin"
    print("[OK] JWT verify succeeds with correct secret")

    # 错误密钥应失败
    try:
        _verify_jwt(token, "wrong-secret")
        assert False, "Should have raised"
    except ValueError:
        print("[OK] JWT verify fails with wrong secret")


def test_jwt_alg_none_attack():
    """测试 alg:none 攻击向量——靶机训练场景。"""
    from llamafw.app import _create_jwt, _verify_jwt

    payload = {"sub": "admin", "role": "admin", "exp": int(time.time()) + 3600}
    token = _create_jwt(payload, "", "none")

    parts = token.split(".")
    assert len(parts) == 3
    assert parts[2] == ""  # none 算法的签名为空
    print("[OK] JWT alg:none produces empty signature")

    # 默认允许 none 算法（训练环境）
    verified = _verify_jwt(token, "any-secret")
    assert verified["sub"] == "admin"
    print("[OK] JWT alg:none accepted in training mode")


def test_jwt_expiration():
    """测试 JWT 过期校验。"""
    from llamafw.app import _create_jwt, _verify_jwt

    secret = "test-secret"
    payload = {"sub": "user", "exp": int(time.time()) - 60}  # 已过期
    token = _create_jwt(payload, secret, "HS256")

    try:
        _verify_jwt(token, secret)
        assert False, "Should have raised for expired token"
    except ValueError as e:
        assert "expired" in str(e).lower() or "exp" in str(e).lower()
        print(f"[OK] JWT expired detection: {e}")


def test_api_key_parsing():
    """测试 API Key 解析函数。"""
    from llamafw.config import LAB_API_KEYS, _parse_api_keys

    # 默认 key 池应包含至少 3 个 key
    assert len(LAB_API_KEYS) >= 3
    roles = {v["role"] for v in LAB_API_KEYS.values()}
    assert "admin" in roles
    print(f"[OK] API keys pool: {len(LAB_API_KEYS)} keys, roles={roles}")

    # 自定义解析
    custom = _parse_api_keys("app1:sk-custom-001:admin,app2:sk-custom-002:viewer")
    assert len(custom) == 2
    assert custom["sk-custom-001"]["role"] == "admin"
    assert custom["sk-custom-002"]["name"] == "app2"
    print("[OK] API key parsing works for custom input")


def test_auth_status_guest():
    """测试未登录状态下的 auth/status 端点。"""
    from llamafw.app import app
    client = TestClient(app)
    response = client.get("/api/v1/auth/status")
    assert response.status_code == 200
    data = response.json()
    assert data["authenticated"] is False
    assert "modes_active" in data
    print("[OK] auth/status reports unauthenticated with mode info")


def test_token_endpoint_requires_credentials():
    """测试 JWT token 端点需要正确凭据。"""
    from llamafw.app import app
    client = TestClient(app)

    # 错误凭据应返回 401
    response = client.post("/api/v1/auth/token", json={
        "username": "admin", "password": "wrong-password"
    })
    assert response.status_code == 401
    print("[OK] token endpoint rejects bad credentials")

    # 正确凭据应返回 token
    response = client.post("/api/v1/auth/token", json={
        "username": "admin", "password": "admin"
    })
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert data["algorithm"] == "HS256"
    print("[OK] token endpoint returns JWT with correct credentials")


def test_jwt_token_verify_endpoint():
    """测试 JWT token 验证端点。"""
    from llamafw.app import app, _create_jwt
    from llamafw.config import LAB_JWT_SECRET

    client = TestClient(app)

    # 创建有效 token
    payload = {"sub": "admin", "role": "admin", "iat": int(time.time()), "exp": int(time.time()) + 3600}
    token = _create_jwt(payload, LAB_JWT_SECRET, "HS256")

    response = client.post("/api/v1/auth/token/verify", headers={
        "Authorization": f"Bearer {token}"
    })
    assert response.status_code == 200
    data = response.json()
    assert data["valid"] is True
    assert data["payload"]["sub"] == "admin"
    print("[OK] JWT verify endpoint validates token correctly")


def test_token_debug_endpoint():
    """测试 JWT debug 端点暴露的元数据。"""
    from llamafw.app import app
    client = TestClient(app)
    response = client.get("/api/v1/auth/token/debug")
    assert response.status_code == 200
    data = response.json()
    assert data["algorithm"] == "HS256"
    assert "secret_hint" in data
    assert "secret_length" in data
    assert "training_focus" in data
    print("[OK] JWT debug endpoint works for training recon")


def test_apikey_endpoints_require_admin():
    """测试 API Key 管理端点需要 admin 权限。"""
    from llamafw.app import app
    client = TestClient(app)

    # 未认证访问应被拒绝
    response = client.get("/api/v1/auth/apikeys")
    assert response.status_code == 403
    print("[OK] apikeys list requires auth")

    response = client.post("/api/v1/auth/apikey", json={"name": "testkey", "role": "user"})
    assert response.status_code == 403
    print("[OK] apikey creation requires auth")


def test_middleware_injects_auth_header():
    """测试认证后中间件注入 X-Auth-Method 响应头。"""
    from llamafw.app import app
    from llamafw.config import LAB_API_KEYS

    client = TestClient(app)

    # 找一个有效的 API key
    valid_key = next(iter(LAB_API_KEYS.keys()))

    # 用 API Key 访问需要认证的 API 端点（/api/v1/user/me 会被中间件拦截）
    response = client.get("/api/v1/user/me", headers={
        "x-api-key": valid_key
    })
    # 中间件应注入 x-auth-method 响应头（FastAPI 会将 header 名小写化）
    assert response.headers.get("x-auth-method") == "apikey"
    print("[OK] API key auth passes middleware, X-Auth-Method header injected")


if __name__ == "__main__":
    test_auth_modes_endpoint()
    test_health_includes_auth_info()
    test_jwt_create_and_verify()
    test_jwt_alg_none_attack()
    test_jwt_expiration()
    test_api_key_parsing()
    test_auth_status_guest()
    test_token_endpoint_requires_credentials()
    test_jwt_token_verify_endpoint()
    test_token_debug_endpoint()
    test_apikey_endpoints_require_admin()
    test_middleware_injects_auth_header()
    print("\n=== All auth multi-mode tests passed ===")
