from base64 import b64decode, b64encode
from datetime import datetime
from hashlib import sha256
from pathlib import Path
import tempfile
from typing import Annotated, Tuple, Union

from crypt4gh_recryptor_service.app import app, common_info
from crypt4gh_recryptor_service.config import get_user_settings, UserSettings
from crypt4gh_recryptor_service.util import run_in_subprocess
from fastapi import Depends
from pydantic import BaseModel, Field, validator


class UserRecryptParams(BaseModel):
    crypt4gh_header: str = Field(..., min_length=1)


class UserRecryptResponse(BaseModel):
    crypt4gh_header: str = Field(..., min_length=1)
    crypt4gh_compute_keypair_id: str = Field(..., min_length=1)
    crypt4gh_compute_keypair_expiration_date: Union[datetime, str]

    @validator('crypt4gh_compute_keypair_expiration_date')
    def to_iso(cls, v):
        if isinstance(v, str):
            v = datetime(v)
        return v.isoformat(timespec='minutes')


@app.get('/info')
async def info(settings: Annotated[UserSettings, Depends(get_user_settings)]) -> dict:
    return common_info(settings)


def _write_orig_header_to_file(crypt4gh_header: str, settings: UserSettings) -> Path:
    header = b64decode(crypt4gh_header)
    filename = sha256(header).hexdigest()
    path = Path(settings.headers_dir, filename)
    with open(path, 'wb') as header_file:
        header_file.write(header)
    path.chmod(mode=0o600)
    return path


def _get_temp_header_filename(settings: UserSettings) -> Path:
    return Path(tempfile.mktemp(dir=settings.headers_dir))


def _rename_temp_header(temp_header_path: Path, settings: UserSettings) -> Tuple[str, str]:
    with open(temp_header_path, 'rb') as header_file:
        header = header_file.read()
    new_filename = sha256(header).hexdigest()
    new_path = Path(settings.headers_dir, new_filename)
    temp_header_path.rename(new_path)
    new_path.chmod(mode=0o600)
    return new_filename, b64encode(header).decode('ascii')


@app.post('/recrypt_header')
async def recrypt_header(
        params: UserRecryptParams,
        settings: Annotated[UserSettings, Depends(get_user_settings)]) -> UserRecryptResponse:
    in_header_path = _write_orig_header_to_file(params.crypt4gh_header, settings)
    out_header_path = _get_temp_header_filename(settings)
    run_in_subprocess(
        f'crypt4gh-recryptor recrypt '
        f'--encryption-key {settings.compute_public_key_path} '
        f'-i {in_header_path} '
        f'-o {out_header_path} '
        f'--decryption-key {settings.user_private_key_path}',
        verbose=settings.dev_mode)
    recrypted_header_path, header = _rename_temp_header(out_header_path, settings)

    return UserRecryptResponse(
        crypt4gh_header=header,
        crypt4gh_compute_keypair_id=recrypted_header_path[-8:],
        crypt4gh_compute_keypair_expiration_date='2023-06-30T12:15',
    )
