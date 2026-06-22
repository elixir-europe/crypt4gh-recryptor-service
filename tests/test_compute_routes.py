import base64
from datetime import datetime, timedelta
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace

import crypt4gh_recryptor_service.compute as compute_module
import pytest
from crypt4gh_recryptor_service.app import app
from crypt4gh_recryptor_service.config import ComputeSettings, ServerMode, get_compute_settings, setup_files
from crypt4gh_recryptor_service.util import ensure_dirs
from fastapi.testclient import TestClient


VALID_HEADER = base64.b64encode(b"header-bytes").decode("ascii")
RECRYPTED_HEADER = base64.b64encode(b"rewritten-header").decode("ascii")


def _create_expired_keypair(settings: ComputeSettings, user_public_key: str, key_id: str) -> None:
    user_hash = sha256(user_public_key.encode("utf8")).hexdigest()
    user_key_path = settings.user_keys_dir.joinpath(user_hash)
    user_key_path.write_text(user_public_key)

    expired_at = (datetime.now() - timedelta(minutes=10)).isoformat(timespec="seconds")
    key_dir = settings.compute_keys_dir.joinpath(user_hash, expired_at, key_id)
    ensure_dirs(key_dir)
    key_dir.joinpath(f"{key_id}.pub").write_text("expired-public-key")
    key_dir.joinpath(f"{key_id}.priv").write_text("expired-private-key")


def _issue_compute_key(client: TestClient, user_public_key: str) -> dict:
    response = client.post(
        "/get_compute_key_info",
        json={"crypt4gh_user_public_key": user_public_key},
    )
    assert response.status_code == 200
    return response.json()


@pytest.fixture(autouse=True)
def fake_generate_keypair(monkeypatch):
    async def _fake_generate_keypair(
        private_key_path: Path,
        public_key_path: Path,
        _passphrase: str,
        _comment: str,
        verbose: bool = False,
    ) -> None:
        private_key_path.write_text("compute-private-key")
        public_key_path.write_text("compute-public-key")
        if verbose:
            pass

    monkeypatch.setattr(compute_module, "crypt4gh_generate_keypair", _fake_generate_keypair)


@pytest.fixture
def fake_recrypt_header(monkeypatch):
    async def _fake_recrypt(
        _in_header_file,
        _decryption_key_path,
        _encryption_key_path,
        verbose: bool,
    ):
        if verbose:
            pass
        return SimpleNamespace(contents=RECRYPTED_HEADER)

    monkeypatch.setattr(compute_module, "crypt4gh_recrypt_header", _fake_recrypt, raising=False)


@pytest.fixture
def configured_client(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    setup_files(ServerMode.COMPUTE)
    settings = ComputeSettings()
    for path in (settings.user_keys_dir, settings.compute_keys_dir, settings.headers_dir):
        ensure_dirs(path)

    app.dependency_overrides[get_compute_settings] = lambda: settings
    with TestClient(app) as client:
        yield client, settings
    app.dependency_overrides.clear()


def test_get_compute_key_info_reuses_keypair_and_persists_hashed_user_key(configured_client):
    client, settings = configured_client
    user_public_key = "-----BEGIN CRYPT4GH PUBLIC KEY-----\nuser-key\n-----END CRYPT4GH PUBLIC KEY-----"

    first = _issue_compute_key(client, user_public_key)
    second = _issue_compute_key(client, user_public_key)

    assert first["crypt4gh_compute_keypair_id"] == second["crypt4gh_compute_keypair_id"]
    assert first["crypt4gh_compute_keypair_expiration_date"] == second[
        "crypt4gh_compute_keypair_expiration_date"
    ]

    user_hash = sha256(user_public_key.encode("utf8")).hexdigest()
    assert settings.user_keys_dir.joinpath(user_hash).exists()
    assert settings.compute_keys_dir.joinpath(user_hash).exists()


def test_recrypt_header_to_job_key_returns_expected_contract(configured_client, fake_recrypt_header):
    client, _settings = configured_client
    user_public_key = "-----BEGIN CRYPT4GH PUBLIC KEY-----\nuser-key\n-----END CRYPT4GH PUBLIC KEY-----"
    key_info = _issue_compute_key(client, user_public_key)

    response = client.post(
        "/recrypt_header_to_job_key",
        json={
            "crypt4gh_header": VALID_HEADER,
            "crypt4gh_compute_keypair_id": key_info["crypt4gh_compute_keypair_id"],
            "crypt4gh_job_public_key": "-----BEGIN CRYPT4GH PUBLIC KEY-----\njob-key\n-----END CRYPT4GH PUBLIC KEY-----",
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["crypt4gh_header"] == RECRYPTED_HEADER
    assert payload["crypt4gh_compute_keypair_id"] == key_info["crypt4gh_compute_keypair_id"]
    assert payload["crypt4gh_compute_keypair_expiration_date"] == key_info[
        "crypt4gh_compute_keypair_expiration_date"
    ]
    assert payload["crypt4gh_compute_public_key"] == key_info["crypt4gh_compute_public_key"]


def test_recrypt_header_to_job_key_returns_404_for_unknown_key_id(configured_client):
    client, _settings = configured_client

    response = client.post(
        "/recrypt_header_to_job_key",
        json={
            "crypt4gh_header": VALID_HEADER,
            "crypt4gh_compute_keypair_id": "cnk:does-not-exist",
            "crypt4gh_job_public_key": "-----BEGIN CRYPT4GH PUBLIC KEY-----\njob-key\n-----END CRYPT4GH PUBLIC KEY-----",
        },
    )

    assert response.status_code == 404
    assert response.json() == {"detail": "Unknown crypt4gh_compute_keypair_id"}


def test_recrypt_header_to_job_key_returns_410_for_expired_key_id(configured_client):
    client, settings = configured_client
    key_id = "cnk:expired"
    user_public_key = "-----BEGIN CRYPT4GH PUBLIC KEY-----\nuser-key\n-----END CRYPT4GH PUBLIC KEY-----"
    _create_expired_keypair(settings, user_public_key, key_id)

    response = client.post(
        "/recrypt_header_to_job_key",
        json={
            "crypt4gh_header": VALID_HEADER,
            "crypt4gh_compute_keypair_id": key_id,
            "crypt4gh_job_public_key": "-----BEGIN CRYPT4GH PUBLIC KEY-----\njob-key\n-----END CRYPT4GH PUBLIC KEY-----",
        },
    )

    assert response.status_code == 410
    assert response.json() == {"detail": "Expired crypt4gh_compute_keypair_id"}


def test_recrypt_header_to_job_key_returns_422_for_malformed_header(
    configured_client,
    fake_recrypt_header,
):
    client, _settings = configured_client
    user_public_key = "-----BEGIN CRYPT4GH PUBLIC KEY-----\nuser-key\n-----END CRYPT4GH PUBLIC KEY-----"
    key_info = _issue_compute_key(client, user_public_key)

    response = client.post(
        "/recrypt_header_to_job_key",
        json={
            "crypt4gh_header": "not-base64!!!",
            "crypt4gh_compute_keypair_id": key_info["crypt4gh_compute_keypair_id"],
            "crypt4gh_job_public_key": "-----BEGIN CRYPT4GH PUBLIC KEY-----\njob-key\n-----END CRYPT4GH PUBLIC KEY-----",
        },
    )

    assert response.status_code == 422
    assert response.json() == {"detail": "Malformed or undecryptable crypt4gh_header"}


def test_recrypt_header_to_user_key_returns_expected_contract(configured_client, fake_recrypt_header):
    client, _settings = configured_client
    user_public_key = "-----BEGIN CRYPT4GH PUBLIC KEY-----\nuser-key\n-----END CRYPT4GH PUBLIC KEY-----"
    key_info = _issue_compute_key(client, user_public_key)

    response = client.post(
        "/recrypt_header_to_user_key",
        json={
            "crypt4gh_header": VALID_HEADER,
            "crypt4gh_compute_keypair_id": key_info["crypt4gh_compute_keypair_id"],
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["crypt4gh_header"] == RECRYPTED_HEADER
    assert payload["crypt4gh_compute_keypair_id"] == key_info["crypt4gh_compute_keypair_id"]
    assert payload["crypt4gh_compute_keypair_expiration_date"] == key_info[
        "crypt4gh_compute_keypair_expiration_date"
    ]


def test_recrypt_header_to_user_key_returns_404_for_unknown_key_id(configured_client):
    client, _settings = configured_client

    response = client.post(
        "/recrypt_header_to_user_key",
        json={
            "crypt4gh_header": VALID_HEADER,
            "crypt4gh_compute_keypair_id": "cnk:does-not-exist",
        },
    )

    assert response.status_code == 404
    assert response.json() == {"detail": "Unknown crypt4gh_compute_keypair_id"}


def test_recrypt_header_to_user_key_returns_410_for_expired_key_id(configured_client):
    client, settings = configured_client
    key_id = "cnk:expired"
    user_public_key = "-----BEGIN CRYPT4GH PUBLIC KEY-----\nuser-key\n-----END CRYPT4GH PUBLIC KEY-----"
    _create_expired_keypair(settings, user_public_key, key_id)

    response = client.post(
        "/recrypt_header_to_user_key",
        json={
            "crypt4gh_header": VALID_HEADER,
            "crypt4gh_compute_keypair_id": key_id,
        },
    )

    assert response.status_code == 410
    assert response.json() == {"detail": "Expired crypt4gh_compute_keypair_id"}


def test_recrypt_header_to_user_key_returns_422_for_malformed_header(
    configured_client,
    fake_recrypt_header,
):
    client, _settings = configured_client
    user_public_key = "-----BEGIN CRYPT4GH PUBLIC KEY-----\nuser-key\n-----END CRYPT4GH PUBLIC KEY-----"
    key_info = _issue_compute_key(client, user_public_key)

    response = client.post(
        "/recrypt_header_to_user_key",
        json={
            "crypt4gh_header": "not-base64!!!",
            "crypt4gh_compute_keypair_id": key_info["crypt4gh_compute_keypair_id"],
        },
    )

    assert response.status_code == 422
    assert response.json() == {"detail": "Malformed or undecryptable crypt4gh_header"}
