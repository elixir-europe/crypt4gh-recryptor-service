import asyncio
import base64
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
from pathlib import Path
import shlex
from types import SimpleNamespace

from crypt4gh_recryptor_service.app import app
import crypt4gh_recryptor_service.compute as compute_module
from crypt4gh_recryptor_service.config import (ComputeSettings,
                                               get_compute_settings,
                                               ServerMode,
                                               setup_files)
import crypt4gh_recryptor_service.crypt as crypt_module
from crypt4gh_recryptor_service.storage import ComputeKeyFile, HeaderFile
from crypt4gh_recryptor_service.util import ensure_dirs
from fastapi import HTTPException
from fastapi.testclient import TestClient
import pytest

VALID_HEADER = base64.b64encode(b'header-bytes').decode('ascii')
RECRYPTED_HEADER = base64.b64encode(b'rewritten-header').decode('ascii')


def _compute_key_index_path(settings: ComputeSettings, key_id: str) -> Path:
    key_id_suffix = key_id.split(':', 1)[1] if ':' in key_id else key_id
    shard = key_id_suffix[:2] if len(key_id_suffix) >= 2 else (key_id_suffix or '__')
    return settings.compute_keys_dir.joinpath('index', shard, f'{key_id}.json')


def _create_expired_keypair(settings: ComputeSettings, user_public_key: str, key_id: str) -> None:
    user_hash = sha256(user_public_key.encode('utf8')).hexdigest()
    user_key_path = settings.user_keys_dir.joinpath(user_hash)
    user_key_path.write_text(user_public_key)

    expired_at = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat(timespec='seconds')
    key_dir = settings.compute_keys_dir.joinpath(user_hash, expired_at, key_id)
    ensure_dirs(key_dir)
    key_dir.joinpath(f'{key_id}.pub').write_text('expired-public-key')
    key_dir.joinpath(f'{key_id}.priv').write_text('expired-private-key')


def _issue_compute_key(client: TestClient, user_public_key: str) -> dict:
    response = client.post(
        '/get_compute_key_info',
        json={'crypt4gh_user_public_key': user_public_key},
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
        private_key_path.write_text('compute-private-key')
        public_key_path.write_text('compute-public-key')
        if verbose:
            pass

    monkeypatch.setattr(compute_module, 'crypt4gh_generate_keypair', _fake_generate_keypair)


@pytest.fixture
def fake_recrypt_header(monkeypatch):
    async def _fake_recrypt(
        _in_header_file,
        _decryption_key_path,
        _encryption_key_path,
        verbose: bool,
        decryption_passphrase: str | None = None,
    ):
        if decryption_passphrase:
            pass
        if verbose:
            pass
        return SimpleNamespace(contents=RECRYPTED_HEADER)

    monkeypatch.setattr(compute_module, 'crypt4gh_recrypt_header', _fake_recrypt, raising=False)


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


@pytest.fixture
def user_public_key():
    return '-----BEGIN CRYPT4GH PUBLIC KEY-----\nuser-key\n-----END CRYPT4GH PUBLIC KEY-----'


@pytest.fixture
def job_public_key():
    return '-----BEGIN CRYPT4GH PUBLIC KEY-----\njob-key\n-----END CRYPT4GH PUBLIC KEY-----'


def test_get_compute_key_info_reuses_keypair_and_persists_hashed_user_key(
    configured_client,
    user_public_key,
):
    client, settings = configured_client

    first = _issue_compute_key(client, user_public_key)
    second = _issue_compute_key(client, user_public_key)

    assert first['crypt4gh_compute_keypair_id'] == second['crypt4gh_compute_keypair_id']
    assert first['crypt4gh_compute_keypair_expiration_date'] == second[
        'crypt4gh_compute_keypair_expiration_date']

    user_hash = sha256(user_public_key.encode('utf8')).hexdigest()
    assert settings.user_keys_dir.joinpath(user_hash).exists()
    assert settings.compute_keys_dir.joinpath(user_hash).exists()


def test_get_compute_key_info_persists_key_id_index(configured_client, user_public_key):
    client, settings = configured_client

    key_info = _issue_compute_key(client, user_public_key)
    key_id = key_info['crypt4gh_compute_keypair_id']
    index_path = _compute_key_index_path(settings, key_id)
    user_hash = sha256(user_public_key.encode('utf8')).hexdigest()

    assert index_path.exists()
    assert json.loads(index_path.read_text()) == {
        'user_hash': user_hash,
        'expiration': key_info['crypt4gh_compute_keypair_expiration_date'],
    }


def test_get_compute_key_info_returns_timezone_aware_expiration(configured_client):
    client, _settings = configured_client
    user_public_key = "-----BEGIN CRYPT4GH PUBLIC KEY-----\nuser-key\n-----END CRYPT4GH PUBLIC KEY-----"

    key_info = _issue_compute_key(client, user_public_key)
    expiration = datetime.fromisoformat(key_info["crypt4gh_compute_keypair_expiration_date"])

    assert expiration.tzinfo is not None
    assert expiration.utcoffset() is not None


def test_recrypt_header_to_user_key_backfills_key_id_index(
    configured_client,
    fake_recrypt_header,
    user_public_key,
):
    client, settings = configured_client
    key_info = _issue_compute_key(client, user_public_key)
    key_id = key_info['crypt4gh_compute_keypair_id']
    index_path = _compute_key_index_path(settings, key_id)

    assert index_path.exists()
    index_path.unlink()
    assert not index_path.exists()

    response = client.post(
        '/recrypt_header_to_user_key',
        json={
            'crypt4gh_header': VALID_HEADER,
            'crypt4gh_compute_keypair_id': key_id,
        },
    )

    assert response.status_code == 200
    assert index_path.exists()


def test_recrypt_header_to_user_key_deletes_stale_index_entry(configured_client):
    client, settings = configured_client
    key_id = 'cnk:stale'
    index_path = _compute_key_index_path(settings, key_id)
    ensure_dirs(index_path.parent)
    index_path.write_text(
        json.dumps({
            'user_hash': 'deadbeef',
            'expiration': '2099-01-01T00:00:00',
        }))
    assert index_path.exists()

    response = client.post(
        '/recrypt_header_to_user_key',
        json={
            'crypt4gh_header': VALID_HEADER,
            'crypt4gh_compute_keypair_id': key_id,
        },
    )

    assert response.status_code == 404
    assert not index_path.exists()


def test_recrypt_header_to_user_key_rejects_path_traversal_key_id(configured_client):
    client, settings = configured_client
    key_id = 'cnk:../../escape'
    victim_file = settings.compute_keys_dir.joinpath('escape.json')
    victim_file.write_text('{}')
    assert victim_file.exists()

    response = client.post(
        '/recrypt_header_to_user_key',
        json={
            'crypt4gh_header': VALID_HEADER,
            'crypt4gh_compute_keypair_id': key_id,
        },
    )

    assert response.status_code == 404
    assert response.json() == {'detail': 'Unknown crypt4gh_compute_keypair_id'}

    assert victim_file.exists()


def test_delete_index_entry_ignores_invalid_key_id_path_traversal(configured_client):
    _client, settings = configured_client
    victim_file = settings.compute_keys_dir.joinpath('escape.json')
    victim_file.write_text('{}')

    ComputeKeyFile.delete_index_entry(settings.compute_keys_dir, 'cnk:../../escape')

    assert victim_file.exists()


def test_recrypt_header_to_job_key_returns_expected_contract(
    configured_client,
    fake_recrypt_header,
    user_public_key,
    job_public_key,
):
    client, _settings = configured_client
    key_info = _issue_compute_key(client, user_public_key)

    response = client.post(
        '/recrypt_header_to_job_key',
        json={
            'crypt4gh_header': VALID_HEADER,
            'crypt4gh_compute_keypair_id': key_info['crypt4gh_compute_keypair_id'],
            'crypt4gh_job_public_key': job_public_key,
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload['crypt4gh_header'] == RECRYPTED_HEADER
    assert payload['crypt4gh_compute_keypair_id'] == key_info['crypt4gh_compute_keypair_id']
    assert payload['crypt4gh_compute_keypair_expiration_date'] == key_info[
        'crypt4gh_compute_keypair_expiration_date']
    assert payload['crypt4gh_compute_public_key'] == key_info['crypt4gh_compute_public_key']


def test_recrypt_header_to_job_key_returns_500_when_recrypt_runtime_fails(
    configured_client,
    monkeypatch,
    user_public_key,
    job_public_key,
):
    client, _settings = configured_client
    key_info = _issue_compute_key(client, user_public_key)

    async def _boom(*_args, **_kwargs):
        raise RuntimeError('boom')

    monkeypatch.setattr(compute_module, 'crypt4gh_recrypt_header', _boom)

    with pytest.raises(RuntimeError):
        client.post(
            '/recrypt_header_to_job_key',
            json={
                'crypt4gh_header': VALID_HEADER,
                'crypt4gh_compute_keypair_id': key_info['crypt4gh_compute_keypair_id'],
                'crypt4gh_job_public_key': job_public_key,
            },
        )


def test_crypt4gh_recrypt_header_maps_decode_failures_to_422(tmp_path, monkeypatch):
    in_header_file = HeaderFile(tmp_path, VALID_HEADER, write_to_storage=True)

    async def _fail_decode(*_args, **_kwargs):
        raise RuntimeError('["crypt4gh-recryptor recrypt" exited with 1]')

    monkeypatch.setattr(crypt_module, 'async_run_in_subprocess', _fail_decode)

    with pytest.raises(HTTPException) as excinfo:
        asyncio.run(
            crypt_module.crypt4gh_recrypt_header(
                in_header_file,
                tmp_path.joinpath('decryption.key'),
                tmp_path.joinpath('encryption.key'),
                verbose=False,
            ))

    assert excinfo.value.status_code == 422
    assert excinfo.value.detail == 'Malformed or undecryptable crypt4gh_header'


def test_crypt4gh_recrypt_header_does_not_mask_unexpected_runtime_errors(tmp_path, monkeypatch):
    in_header_file = HeaderFile(tmp_path, VALID_HEADER, write_to_storage=True)

    async def _runtime_failure(*_args, **_kwargs):
        raise RuntimeError('subprocess unavailable')

    monkeypatch.setattr(crypt_module, 'async_run_in_subprocess', _runtime_failure)

    with pytest.raises(RuntimeError, match='subprocess unavailable'):
        asyncio.run(
            crypt_module.crypt4gh_recrypt_header(
                in_header_file,
                tmp_path.joinpath('decryption.key'),
                tmp_path.joinpath('encryption.key'),
                verbose=False,
            ))


def test_crypt4gh_recrypt_header_passes_decryption_passphrase_to_subprocess(tmp_path, monkeypatch):
    in_header_file = HeaderFile(tmp_path, VALID_HEADER, write_to_storage=True)
    captured_cmd = ""

    async def _capture_cmd(cmd: str, verbose: bool):
        nonlocal captured_cmd
        captured_cmd = cmd
        parts = shlex.split(cmd)
        output_path = Path(parts[parts.index("-o") + 1])
        output_path.write_bytes(b"stub-header")
        if verbose:
            pass

    monkeypatch.setattr(crypt_module, "async_run_in_subprocess", _capture_cmd)

    asyncio.run(
        crypt_module.crypt4gh_recrypt_header(
            in_header_file,
            tmp_path.joinpath("decryption.key"),
            tmp_path.joinpath("encryption.key"),
            decryption_passphrase="secret-passphrase",
            verbose=False,
        )
    )

    assert "--decryption-passphrase \"secret-passphrase\"" in captured_cmd


def test_recrypt_header_to_job_key_returns_404_for_unknown_key_id(
    configured_client,
    job_public_key,
):
    client, _settings = configured_client

    response = client.post(
        '/recrypt_header_to_job_key',
        json={
            'crypt4gh_header': VALID_HEADER,
            'crypt4gh_compute_keypair_id': 'cnk:does-not-exist',
            'crypt4gh_job_public_key': job_public_key,
        },
    )

    assert response.status_code == 404
    assert response.json() == {'detail': 'Unknown crypt4gh_compute_keypair_id'}


def test_recrypt_header_to_job_key_returns_410_for_expired_key_id(
    configured_client,
    user_public_key,
    job_public_key,
):
    client, settings = configured_client
    key_id = 'cnk:expired'
    _create_expired_keypair(settings, user_public_key, key_id)

    response = client.post(
        '/recrypt_header_to_job_key',
        json={
            'crypt4gh_header': VALID_HEADER,
            'crypt4gh_compute_keypair_id': key_id,
            'crypt4gh_job_public_key': job_public_key,
        },
    )

    assert response.status_code == 410
    assert response.json() == {'detail': 'Expired crypt4gh_compute_keypair_id'}


def test_recrypt_header_to_job_key_returns_422_for_malformed_header(
    configured_client,
    fake_recrypt_header,
    user_public_key,
    job_public_key,
):
    client, _settings = configured_client
    key_info = _issue_compute_key(client, user_public_key)

    response = client.post(
        '/recrypt_header_to_job_key',
        json={
            'crypt4gh_header': 'not-base64!!!',
            'crypt4gh_compute_keypair_id': key_info['crypt4gh_compute_keypair_id'],
            'crypt4gh_job_public_key': job_public_key,
        },
    )

    assert response.status_code == 422
    assert response.json() == {'detail': 'Malformed or undecryptable crypt4gh_header'}


def test_recrypt_header_to_user_key_returns_expected_contract(
    configured_client,
    fake_recrypt_header,
    user_public_key,
):
    client, _settings = configured_client
    key_info = _issue_compute_key(client, user_public_key)

    response = client.post(
        '/recrypt_header_to_user_key',
        json={
            'crypt4gh_header': VALID_HEADER,
            'crypt4gh_compute_keypair_id': key_info['crypt4gh_compute_keypair_id'],
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload['crypt4gh_header'] == RECRYPTED_HEADER
    assert payload['crypt4gh_compute_keypair_id'] == key_info['crypt4gh_compute_keypair_id']
    assert payload['crypt4gh_compute_keypair_expiration_date'] == key_info[
        'crypt4gh_compute_keypair_expiration_date']


def test_recrypt_header_to_user_key_returns_404_for_unknown_key_id(configured_client):
    client, _settings = configured_client

    response = client.post(
        '/recrypt_header_to_user_key',
        json={
            'crypt4gh_header': VALID_HEADER,
            'crypt4gh_compute_keypair_id': 'cnk:does-not-exist',
        },
    )

    assert response.status_code == 404
    assert response.json() == {'detail': 'Unknown crypt4gh_compute_keypair_id'}


def test_recrypt_header_to_user_key_returns_410_for_expired_key_id(
    configured_client,
    user_public_key,
):
    client, settings = configured_client
    key_id = 'cnk:expired'
    _create_expired_keypair(settings, user_public_key, key_id)

    response = client.post(
        '/recrypt_header_to_user_key',
        json={
            'crypt4gh_header': VALID_HEADER,
            'crypt4gh_compute_keypair_id': key_id,
        },
    )

    assert response.status_code == 410
    assert response.json() == {'detail': 'Expired crypt4gh_compute_keypair_id'}


def test_recrypt_header_to_user_key_returns_422_for_malformed_header(
    configured_client,
    fake_recrypt_header,
    user_public_key,
):
    client, _settings = configured_client
    key_info = _issue_compute_key(client, user_public_key)

    response = client.post(
        '/recrypt_header_to_user_key',
        json={
            'crypt4gh_header': 'not-base64!!!',
            'crypt4gh_compute_keypair_id': key_info['crypt4gh_compute_keypair_id'],
        },
    )

    assert response.status_code == 422
    assert response.json() == {'detail': 'Malformed or undecryptable crypt4gh_header'}
