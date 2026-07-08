"""End-to-end auth flow test."""
import sys
sys.path.insert(0, "src")

from fastapi.testclient import TestClient
from llamafw.app import app


def test_auth_flow():
    client = TestClient(app, base_url="https://testserver")

    # 1. 未认证访问首页 → 302 跳转到 /login
    r = client.get("/", follow_redirects=False)
    assert r.status_code == 302 and "/login" in r.headers["location"], f"step 1: expected 302 redirect, got {r.status_code}"

    # 2. 获取登录页
    r = client.get("/login")
    assert r.status_code == 200, f"step 2: expected 200, got {r.status_code}"

    # 3. 错误密码登录
    r = client.post("/login", json={"username": "admin", "password": "wrong"})
    assert r.status_code == 401, f"step 3: expected 401, got {r.status_code}"

    # 4. 正确密码登录
    r = client.post("/login", json={"username": "admin", "password": "admin"})
    assert r.status_code == 200 and r.json()["ok"], f"step 4: login failed"

    # 5. 认证后访问首页
    cookies = dict(r.cookies)
    r = client.get("/", cookies=cookies, follow_redirects=False)
    assert r.status_code == 200, f"step 5: expected 200, got {r.status_code}"

    # 6. API 路由无需认证
    r = client.get("/api/v1/health")
    assert r.status_code == 200, f"step 6: API should be exempt from auth"

    # 7. 禁用认证后直接访问首页
    r = client.post("/api/v1/auth/toggle", cookies=cookies)
    assert r.status_code == 200, f"step 7a: toggle failed: {r.status_code}"
    r = client.get("/", follow_redirects=False)
    assert r.status_code == 200, f"step 7b: auth disabled but got {r.status_code}"

    # 8. 重新启用认证
    r = client.post("/api/v1/auth/toggle", cookies=cookies)
    assert r.status_code == 200, f"step 8: re-enable auth failed: {r.status_code}"

    # 9. 认证状态 API
    r = client.get("/api/v1/auth/status", cookies=cookies)
    assert r.status_code == 200
    data = r.json()
    assert data["authenticated"] is True
    assert data["user"] == "admin"

    # 10. 登出
    r = client.get("/logout", cookies=cookies, follow_redirects=False)
    assert r.status_code == 302 and "/login" in r.headers["location"], f"step 10: logout failed"

    # 11. 登出后访问首页 → 302
    r = client.get("/", follow_redirects=False)
    assert r.status_code == 302 and "/login" in r.headers["location"], f"step 11: should redirect after logout"

    print("ALL 11 TESTS PASSED")


if __name__ == "__main__":
    test_auth_flow()
