from crypt4gh_recryptor_service.app import configure_user_cors
from crypt4gh_recryptor_service.config import UserSettings
from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest
from starlette.middleware.cors import CORSMiddleware

GALAXY_ORIGIN = 'https://galaxy.example.org'
OTHER_ORIGIN = 'https://not-galaxy.example.org'


def _client(allowed_origins) -> TestClient:
    app = FastAPI()

    @app.post('/recrypt_header')
    async def _recrypt_header() -> dict:
        return {}

    configure_user_cors(app, allowed_origins)
    return TestClient(app)


def _preflight(client: TestClient, origin: str, request_headers: str = 'content-type'):
    return client.options(
        '/recrypt_header',
        headers={
            'Origin': origin,
            'Access-Control-Request-Method': 'POST',
            'Access-Control-Request-Headers': request_headers,
        },
    )


def test_browser_access_is_disabled_by_default(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    assert UserSettings().allowed_origins == []

    response = _preflight(_client([]), GALAXY_ORIGIN)
    assert response.status_code == 405
    assert 'access-control-allow-origin' not in response.headers


def test_exact_origins_load_from_user_config(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    working_dir = tmp_path.joinpath('c4gh_recryptor_user')
    working_dir.mkdir()
    working_dir.joinpath('c4gh_config.yml').write_text(f'allowed_origins:\n  - {GALAXY_ORIGIN}\n')

    assert UserSettings().allowed_origins == [GALAXY_ORIGIN]


def test_compute_app_never_installs_cors_middleware():
    from crypt4gh_recryptor_service.compute import app

    assert all(middleware.cls is not CORSMiddleware for middleware in app.user_middleware)


def test_configured_origin_can_preflight_and_read_response():
    client = _client([GALAXY_ORIGIN])

    preflight = _preflight(client, GALAXY_ORIGIN)
    response = client.post('/recrypt_header', headers={'Origin': GALAXY_ORIGIN}, json={})

    assert preflight.status_code == 200
    assert preflight.headers['access-control-allow-origin'] == GALAXY_ORIGIN
    assert response.headers['access-control-allow-origin'] == GALAXY_ORIGIN
    assert 'access-control-allow-credentials' not in preflight.headers
    assert 'access-control-allow-credentials' not in response.headers


def test_other_origin_cannot_preflight_or_read_response():
    client = _client([GALAXY_ORIGIN])

    preflight = _preflight(client, OTHER_ORIGIN)
    response = client.post('/recrypt_header', headers={'Origin': OTHER_ORIGIN}, json={})

    assert preflight.status_code == 400
    assert 'access-control-allow-origin' not in preflight.headers
    assert 'access-control-allow-origin' not in response.headers


def test_authorization_header_is_not_allowed():
    response = _preflight(_client([GALAXY_ORIGIN]), GALAXY_ORIGIN, 'authorization')

    assert response.status_code == 400


@pytest.mark.parametrize(
    'origin',
    [
        '*',
        'null',
        'https://*.example.org',
        'https://galaxy.example.org/',
        'https://galaxy.example.org/path',
        'https://user@galaxy.example.org',
    ],
)
def test_broad_or_malformed_origins_are_rejected(origin):
    with pytest.raises(ValueError, match='Invalid allowed origin'):
        _client([origin])
