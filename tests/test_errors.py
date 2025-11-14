def register_user(
    client, email: str, full_name: str = "Test User", password: str = "password"
):
    response = client.post(
        "/users", json={"email": email, "full_name": full_name, "password": password}
    )
    assert response.status_code == 200
    return response.json()


def login_user(client, email: str, password: str = "password"):
    response = client.post("/auth/login", json={"email": email, "password": password})
    assert response.status_code == 200
    return response.json()["access_token"]


def auth_headers(token: str):
    return {"Authorization": f"Bearer {token}"}


def test_health_check(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_register_and_login(client):
    # Регистрация
    user_data = register_user(client, "test@example.com", "Test User")
    assert user_data["email"] == "test@example.com"
    assert "id" in user_data

    # Вход
    token = login_user(client, "test@example.com")
    assert isinstance(token, str)
    assert len(token) > 0


def test_create_feature_requires_auth(client):
    data = {"title": "Dark mode", "description": "Add dark theme support"}
    # Без токена — 401
    response = client.post("/features", json=data)
    assert response.status_code == 401

    # С токеном — OK
    register_user(client, "user1@example.com")
    token = login_user(client, "user1@example.com")
    response = client.post("/features", json=data, headers=auth_headers(token))
    assert response.status_code == 200
    result = response.json()
    assert result["title"] == "Dark mode"
    assert result["vote_count"] == 0
    assert "id" in result
    assert result["owner_id"] > 0


def test_list_features(client):
    register_user(client, "listuser@example.com")
    token = login_user(client, "listuser@example.com")

    client.post(
        "/features",
        json={"title": "F1", "description": "D1"},
        headers=auth_headers(token),
    )
    client.post(
        "/features",
        json={"title": "F2", "description": "D2"},
        headers=auth_headers(token),
    )

    response = client.get("/features")
    assert response.status_code == 200
    features = response.json()
    assert len(features) == 2


def test_get_feature(client):
    register_user(client, "getuser@example.com")
    token = login_user(client, "getuser@example.com")

    resp = client.post(
        "/features",
        json={"title": "Test", "description": "Desc"},
        headers=auth_headers(token),
    )
    feature_id = resp.json()["id"]

    response = client.get(f"/features/{feature_id}")
    assert response.status_code == 200
    assert response.json()["title"] == "Test"


def test_get_feature_not_found(client):
    response = client.get("/features/999")
    assert response.status_code == 404
    body = response.json()
    assert body["type"] == "https://featurevotes.example.com/errors/not_found"
    assert body["title"] == "Resource not found"
    assert body["detail"] == "Feature not found"
    assert "correlation_id" in body


def test_update_feature(client):
    register_user(client, "updater@example.com")
    token = login_user(client, "updater@example.com")

    resp = client.post(
        "/features",
        json={"title": "Old", "description": "Old desc"},
        headers=auth_headers(token),
    )
    feature_id = resp.json()["id"]

    response = client.put(
        f"/features/{feature_id}",
        json={"title": "Updated", "description": "New desc"},
        headers=auth_headers(token),
    )
    assert response.status_code == 200
    data = response.json()
    assert data["title"] == "Updated"
    assert data["description"] == "New desc"


def test_update_feature_not_owner_forbidden(client):
    # Пользователь 1 создаёт фичу
    register_user(client, "owner@example.com")
    token1 = login_user(client, "owner@example.com")
    resp = client.post(
        "/features",
        json={"title": "Mine", "description": "My feature"},
        headers=auth_headers(token1),
    )
    feature_id = resp.json()["id"]

    # Пользователь 2 пытается обновить
    register_user(client, "intruder@example.com")
    token2 = login_user(client, "intruder@example.com")
    response = client.put(
        f"/features/{feature_id}",
        json={"title": "Hacked", "description": "Nope"},
        headers=auth_headers(token2),
    )
    assert response.status_code == 403


def test_update_feature_not_found(client):
    register_user(client, "user@example.com")
    token = login_user(client, "user@example.com")

    response = client.put(
        "/features/999",
        json={"title": "Updated", "description": "New desc"},
        headers=auth_headers(token),
    )
    assert response.status_code == 404
    body = response.json()
    assert body["type"] == "https://featurevotes.example.com/errors/not_found"
    assert body["title"] == "Resource not found"
    assert body["detail"] == "Feature not found"
    assert "correlation_id" in body


def test_delete_feature(client):
    register_user(client, "deleter@example.com")
    token = login_user(client, "deleter@example.com")

    resp = client.post(
        "/features",
        json={"title": "To delete", "description": "..."},
        headers=auth_headers(token),
    )
    feature_id = resp.json()["id"]

    response = client.delete(f"/features/{feature_id}", headers=auth_headers(token))
    assert response.status_code == 200
    assert response.json() == {"ok": True}


def test_delete_feature_not_owner_forbidden(client):
    register_user(client, "owner2@example.com")
    token1 = login_user(client, "owner2@example.com")
    resp = client.post(
        "/features",
        json={"title": "Mine", "description": "My feature"},
        headers=auth_headers(token1),
    )
    feature_id = resp.json()["id"]

    register_user(client, "other@example.com")
    token2 = login_user(client, "other@example.com")
    response = client.delete(f"/features/{feature_id}", headers=auth_headers(token2))
    assert response.status_code == 403


def test_delete_feature_not_found(client):
    register_user(client, "user@example.com")
    token = login_user(client, "user@example.com")

    response = client.delete("/features/999", headers=auth_headers(token))
    assert response.status_code == 404
    body = response.json()
    assert body["type"] == "https://featurevotes.example.com/errors/not_found"
    assert body["title"] == "Resource not found"
    assert body["detail"] == "Feature not found"
    assert "correlation_id" in body


def test_top_features(client):
    # Создаём 3 пользователей
    emails = ["top1@example.com", "top2@example.com", "top3@example.com"]
    tokens = []
    for email in emails:
        register_user(client, email)
        tokens.append(login_user(client, email))

    # Каждый создаёт по фиче
    f1 = client.post(
        "/features",
        json={"title": "F1", "description": "D1"},
        headers=auth_headers(tokens[0]),
    ).json()
    f2 = client.post(
        "/features",
        json={"title": "F2", "description": "D2"},
        headers=auth_headers(tokens[1]),
    ).json()
    f3 = client.post(
        "/features",
        json={"title": "F3", "description": "D3"},
        headers=auth_headers(tokens[2]),
    ).json()

    # Голосуем: F3 — 3 голоса, F1 — 2, F2 — 1
    client.post(f"/features/{f1['id']}/vote", headers=auth_headers(tokens[0]))
    client.post(f"/features/{f1['id']}/vote", headers=auth_headers(tokens[1]))

    client.post(f"/features/{f2['id']}/vote", headers=auth_headers(tokens[0]))

    client.post(f"/features/{f3['id']}/vote", headers=auth_headers(tokens[0]))
    client.post(f"/features/{f3['id']}/vote", headers=auth_headers(tokens[1]))
    client.post(f"/features/{f3['id']}/vote", headers=auth_headers(tokens[2]))

    response = client.get("/features/top")
    assert response.status_code == 200
    top = response.json()
    assert len(top) == 3
    assert top[0]["title"] == "F3"
    assert top[1]["title"] == "F1"
    assert top[2]["title"] == "F2"


def test_vote_feature(client):
    register_user(client, "voter1@example.com")
    token = login_user(client, "voter1@example.com")

    create_resp = client.post(
        "/features",
        json={"title": "Test Feature", "description": "Test"},
        headers=auth_headers(token),
    )
    assert create_resp.status_code == 200
    feature_id = create_resp.json()["id"]

    vote_resp = client.post(f"/features/{feature_id}/vote", headers=auth_headers(token))
    assert vote_resp.status_code == 200
    assert vote_resp.json()["message"] == "Vote registered"

    get_resp = client.get(f"/features/{feature_id}")
    assert get_resp.json()["vote_count"] == 1


def test_duplicate_vote(client):
    register_user(client, "dupvoter@example.com")
    token = login_user(client, "dupvoter@example.com")

    create_resp = client.post(
        "/features",
        json={"title": "Dup", "description": "..."},
        headers=auth_headers(token),
    )
    feature_id = create_resp.json()["id"]

    client.post(f"/features/{feature_id}/vote", headers=auth_headers(token))
    resp = client.post(f"/features/{feature_id}/vote", headers=auth_headers(token))
    assert resp.status_code == 409
    body = resp.json()
    assert body["type"] == "https://featurevotes.example.com/errors/duplicate_vote"
    assert body["title"] == "Duplicate vote"
    assert body["detail"] == "User has already voted for this feature"
    assert "correlation_id" in body


def test_vote_invalid_feature(client):
    register_user(client, "badvoter@example.com")
    token = login_user(client, "badvoter@example.com")

    response = client.post("/features/999/vote", headers=auth_headers(token))
    assert response.status_code == 404
    body = response.json()
    assert body["type"] == "https://featurevotes.example.com/errors/feature_not_found"
    assert body["title"] == "Feature not found"
    assert body["detail"] == "Feature not found"
    assert "correlation_id" in body


def test_users_me(client):
    register_user(client, "me@example.com", "Denis Me")
    token = login_user(client, "me@example.com")

    response = client.get("/users/me", headers=auth_headers(token))
    assert response.status_code == 200
    data = response.json()
    assert data["email"] == "me@example.com"
    assert data["full_name"] == "Denis Me"


def test_update_user_me(client):
    register_user(client, "updateme@example.com", "Old Name")
    token = login_user(client, "updateme@example.com")

    response = client.put(
        "/users/me", json={"full_name": "New Name"}, headers=auth_headers(token)
    )
    assert response.status_code == 200
    assert response.json()["full_name"] == "New Name"


def test_user_create_email_too_long(client):
    long_email = "a" * 300 + "@example.com"
    resp = client.post(
        "/users",
        json={"email": long_email, "full_name": "Test", "password": "password123"},
    )
    assert resp.status_code == 422


def test_feature_create_empty_title(client):
    register_user(client, "feat@example.com")
    token = login_user(client, "feat@example.com")
    resp = client.post(
        "/features",
        json={"title": "", "description": "Valid desc"},
        headers=auth_headers(token),
    )
    assert resp.status_code == 422


def test_password_too_short(client):
    resp = client.post(
        "/users",
        json={"email": "shortpass@example.com", "full_name": "Test", "password": "123"},
    )
    assert resp.status_code == 422


def test_description_too_long(client):
    register_user(client, "longdesc@example.com")
    token = login_user(client, "longdesc@example.com")
    resp = client.post(
        "/features",
        json={"title": "OK", "description": "x" * 1001},
        headers=auth_headers(token),
    )
    assert resp.status_code == 422


def test_register_user_duplicate_email(client):
    email = "unique@example.com"
    register_user(client, email)
    response = client.post(
        "/users",
        json={"email": email, "full_name": "Another User", "password": "anotherpass"},
    )
    assert response.status_code == 400
    body = response.json()
    assert "email_exists" in body["type"]
    assert body["title"] == "Email already registered"
    assert body["detail"] == "Проверьте почту, если адрес подтверждён"


def test_login_invalid_credentials_wrong_password(client):
    email = "login@example.com"
    password = "password"
    register_user(client, email, "Login User", password)
    response = client.post(
        "/auth/login", json={"email": email, "password": "wrongpassword"}
    )
    assert response.status_code == 401
    body = response.json()
    assert "invalid_credentials" in body["type"]
    assert body["title"] == "Invalid credentials"
    assert body["detail"] == "Неверные данные аккаунта"


def test_login_invalid_credentials_nonexistent_user(client):
    response = client.post(
        "/auth/login",
        json={"email": "nonexistent@example.com", "password": "any_password"},
    )
    assert response.status_code == 401
    body = response.json()
    assert "invalid_credentials" in body["type"]
    assert body["title"] == "Invalid credentials"
    assert body["detail"] == "Неверные данные аккаунта"


def test_login_missing_email_field(client):
    response = client.post("/auth/login", json={"password": "password"})
    assert response.status_code == 422


def test_login_missing_password_field(client):
    response = client.post("/auth/login", json={"email": "test@example.com"})
    assert response.status_code == 422


def test_login_empty_email(client):
    response = client.post("/auth/login", json={"email": "", "password": "password"})
    assert response.status_code == 422


def test_login_empty_password(client):
    response = client.post(
        "/auth/login", json={"email": "test@example.com", "password": ""}
    )
    assert response.status_code in [401, 422]


def test_access_protected_route_without_token(client):
    response = client.get("/users/me")
    assert response.status_code == 401
    body = response.json()
    assert body["detail"] == "Not authenticated"


def test_access_protected_route_with_invalid_token_format(client):
    headers = {"Authorization": "InvalidFormatToken"}
    response = client.get("/users/me", headers=headers)
    assert response.status_code == 401
    body = response.json()
    assert body["detail"] == "Not authenticated"


def test_access_protected_route_with_malformed_token(client):
    headers = {"Authorization": "Bearer invalid.token.format"}
    response = client.get("/users/me", headers=headers)
    assert response.status_code == 401
    body = response.json()
    assert body["title"] == "Unauthorized"


def test_access_protected_route_with_invalid_signature_token(client):
    from datetime import datetime, timedelta

    from jose import jwt

    payload = {"sub": "1", "exp": datetime.utcnow() + timedelta(minutes=30)}
    tampered_token = jwt.encode(payload, "wrong_secret_key", algorithm="HS256")
    headers = {"Authorization": f"Bearer {tampered_token}"}
    response = client.get("/users/me", headers=headers)
    assert response.status_code == 401
    body = response.json()
    assert body["title"] == "Unauthorized"


def test_register_user_invalid_email_format(client):
    response = client.post(
        "/users",
        json={
            "email": "invalid-email",
            "full_name": "Test User",
            "password": "password",
        },
    )
    assert response.status_code == 422


def test_register_user_empty_email(client):
    response = client.post(
        "/users", json={"email": "", "full_name": "Test User", "password": "password"}
    )
    assert response.status_code == 422


def test_register_user_empty_password(client):
    response = client.post(
        "/users",
        json={"email": "valid@example.com", "full_name": "Test User", "password": ""},
    )
    assert response.status_code == 422


def test_register_user_empty_full_name(client):
    response = client.post(
        "/users",
        json={"email": "valid@example.com", "full_name": "", "password": "password"},
    )
    assert response.status_code == 422


def test_register_user_missing_email_field(client):
    response = client.post(
        "/users", json={"full_name": "Test User", "password": "password"}
    )
    assert response.status_code == 422


def test_register_user_missing_password_field(client):
    response = client.post(
        "/users", json={"email": "valid@example.com", "full_name": "Test User"}
    )
    assert response.status_code == 422


def test_register_user_missing_full_name_field(client):
    response = client.post(
        "/users", json={"email": "valid@example.com", "password": "password"}
    )
    assert response.status_code == 422


def test_update_user_me_empty_full_name(client):
    register_user(client, "updateempty@example.com", "Old Name")
    token = login_user(client, "updateempty@example.com")
    response = client.put(
        "/users/me", json={"full_name": ""}, headers=auth_headers(token)
    )
    assert response.status_code == 422


def test_update_user_me_missing_full_name_field(client):
    register_user(client, "updatemissing@example.com", "Old Name")
    token = login_user(client, "updatemissing@example.com")
    response = client.put("/users/me", json={}, headers=auth_headers(token))
    assert response.status_code == 422


def test_create_feature_empty_title(client):
    register_user(client, "emptytitle@example.com")
    token = login_user(client, "emptytitle@example.com")
    response = client.post(
        "/features",
        json={"title": "", "description": "Valid desc"},
        headers=auth_headers(token),
    )
    assert response.status_code == 422


def test_create_feature_missing_title_field(client):
    register_user(client, "missingtitle@example.com")
    token = login_user(client, "missingtitle@example.com")
    response = client.post(
        "/features",
        json={"description": "Valid desc"},
        headers=auth_headers(token),
    )
    assert response.status_code == 422


def test_create_feature_empty_description(client):
    register_user(client, "emptydesc@example.com")
    token = login_user(client, "emptydesc@example.com")
    response = client.post(
        "/features",
        json={"title": "Valid Title", "description": None},
        headers=auth_headers(token),
    )
    assert response.status_code == 422


def test_update_feature_empty_title(client):
    register_user(client, "updaterempty@example.com")
    token = login_user(client, "updaterempty@example.com")
    resp = client.post(
        "/features",
        json={"title": "Old", "description": "Old desc"},
        headers=auth_headers(token),
    )
    feature_id = resp.json()["id"]
    response = client.put(
        f"/features/{feature_id}",
        json={"title": "", "description": "New desc"},
        headers=auth_headers(token),
    )
    assert response.status_code == 422


def test_update_feature_missing_title_field(client):
    register_user(client, "updatermissing@example.com")
    token = login_user(client, "updatermissing@example.com")
    resp = client.post(
        "/features",
        json={"title": "Old", "description": "Old desc"},
        headers=auth_headers(token),
    )
    feature_id = resp.json()["id"]
    response = client.put(
        f"/features/{feature_id}",
        json={"description": "New desc"},
        headers=auth_headers(token),
    )
    assert response.status_code == 422


def test_update_feature_missing_description_field(client):
    register_user(client, "updatermissingdesc@example.com")
    token = login_user(client, "updatermissingdesc@example.com")
    resp = client.post(
        "/features",
        json={"title": "Old", "description": "Old desc"},
        headers=auth_headers(token),
    )
    feature_id = resp.json()["id"]
    response = client.put(
        f"/features/{feature_id}",
        json={"title": "New Title"},
        headers=auth_headers(token),
    )
    assert response.status_code == 422


def test_update_feature_non_numeric_id(client):
    register_user(client, "updaterstr@example.com")
    token = login_user(client, "updaterstr@example.com")
    response = client.put(
        "/features/invalid_id",
        json={"title": "New Title", "description": "New Desc"},
        headers=auth_headers(token),
    )
    assert response.status_code == 422


def test_update_feature_negative_id(client):
    register_user(client, "updaterneg@example.com")
    token = login_user(client, "updaterneg@example.com")
    response = client.put(
        "/features/-1",
        json={"title": "New Title", "description": "New Desc"},
        headers=auth_headers(token),
    )
    assert response.status_code == 404
    body = response.json()
    assert "not_found" in body["type"]


def test_delete_feature_non_numeric_id(client):
    register_user(client, "deleterstr@example.com")
    token = login_user(client, "deleterstr@example.com")
    response = client.delete(
        "/features/invalid_id",
        headers=auth_headers(token),
    )
    assert response.status_code == 422


def test_delete_feature_negative_id(client):
    register_user(client, "deleteneg@example.com")
    token = login_user(client, "deleteneg@example.com")
    response = client.delete(
        "/features/-1",
        headers=auth_headers(token),
    )
    assert response.status_code == 404
    body = response.json()
    assert "not_found" in body["type"]


def test_get_feature_non_numeric_id(client):
    response = client.get("/features/invalid_id")
    assert response.status_code == 422


def test_get_feature_negative_id(client):
    response = client.get("/features/-1")
    assert response.status_code == 404
    body = response.json()
    assert "not_found" in body["type"]


def test_vote_feature_non_numeric_id(client):
    register_user(client, "voterstr@example.com")
    token = login_user(client, "voterstr@example.com")
    response = client.post(
        "/features/invalid_id/vote",
        headers=auth_headers(token),
    )
    assert response.status_code == 422


def test_vote_feature_negative_id(client):
    register_user(client, "voterneg@example.com")
    token = login_user(client, "voterneg@example.com")
    response = client.post(
        "/features/-1/vote",
        headers=auth_headers(token),
    )
    assert response.status_code == 404
    body = response.json()
    assert "feature_not_found" in body["type"]
