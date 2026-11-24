"""[X1] No endpoint may issue a token from a username alone."""


def test_refresh_token_by_username_is_gone(client, clean_db, make_user):
    user = make_user("patient")
    r = client.post("/api/refresh_token", json={"username": user["username"]})
    assert r.status_code == 404
    body = r.get_data(as_text=True)
    assert "access_token" not in body
