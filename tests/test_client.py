from google.auth.credentials import AnonymousCredentials

from vibeguardian.gcp import client


def test_session_retries_api_calls_and_token_refreshes(monkeypatch):
    monkeypatch.setattr(client.google.auth, "default", lambda scopes: (AnonymousCredentials(), None))
    http = client.session()
    api_retry = http.get_adapter("https://apikeys.googleapis.com").max_retries
    token_retry = http._auth_request.session.get_adapter("https://oauth2.googleapis.com").max_retries
    assert api_retry.connect == 5
    assert "POST" not in api_retry.allowed_methods
    assert "POST" in token_retry.allowed_methods


def test_quota_project_only_applies_to_user_credentials(monkeypatch):
    from google.oauth2.credentials import Credentials

    user = Credentials(token="t")
    monkeypatch.setattr(client.google.auth, "default", lambda scopes: (user, None))
    assert client.session(quota_project="p").credentials.quota_project_id == "p"

    anonymous = AnonymousCredentials()
    monkeypatch.setattr(client.google.auth, "default", lambda scopes: (anonymous, None))
    assert client.session(quota_project="p").credentials is anonymous


def test_api_posts_are_never_retried_after_reaching_google():
    assert "POST" not in client.RETRY.allowed_methods
