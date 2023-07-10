from abc import abstractmethod
from base64 import b64decode, b64encode
from datetime import datetime
from hashlib import sha256
from pathlib import Path
from subprocess import CalledProcessError
import tempfile
from typing import Annotated, Generic, Optional, TypeVar, Union

from crypt4gh_recryptor_service.app import app, common_info
from crypt4gh_recryptor_service.compute import ComputeKeyInfoParams, ComputeKeyInfoResponse
from crypt4gh_recryptor_service.config import get_user_settings, UserSettings
from crypt4gh_recryptor_service.util import run_in_subprocess
from crypt4gh_recryptor_service.validators import to_iso
from fastapi import Depends, HTTPException, Request
from pydantic import BaseModel, Field, parse_obj_as, validator


class UserRecryptParams(BaseModel):
    crypt4gh_header: str = Field(..., min_length=1)


class UserRecryptResponse(BaseModel):
    crypt4gh_header: str = Field(..., min_length=1)
    crypt4gh_compute_keypair_id: str = Field(..., min_length=1)
    crypt4gh_compute_keypair_expiration_date: Union[datetime, str]

    _to_iso = validator('crypt4gh_compute_keypair_expiration_date', allow_reuse=True)(to_iso)


@app.get('/info')
async def info(settings: Annotated[UserSettings, Depends(get_user_settings)]) -> dict:
    return common_info(settings)


T = TypeVar('T', bytes, str)


class HashedFile(Generic[T]):
    def __init__(self, dir: Path, contents: Optional[T] = None):
        self._dir: Path = dir
        self._contents: Optional[bytes] = self._to_bytes(contents) if contents else None
        self._filename: str = self.sha256 if self._contents else tempfile.mktemp(dir=self._dir)

    @classmethod
    def _to_bytes(cls, contents: T) -> bytes:
        assert isinstance(contents, bytes)
        return contents

    @property
    @abstractmethod
    def contents(self) -> T:
        ...

    @property
    def sha256(self):
        return sha256(self._contents).hexdigest()

    @property
    def path(self) -> Path:
        return self._dir.joinpath(self._filename)

    def write_to_storage(self):
        assert self._contents is not None
        with open(self.path, 'wb') as hashed_file:
            hashed_file.write(self._contents)
        self.path.chmod(mode=0o600)

    def read_from_storage(self):
        with open(self.path, 'rb') as hashed_file:
            self._contents = hashed_file.read()
            if self._filename != self.sha256:
                self.path.rename(self._dir.joinpath(self.sha256))


class HashedBytesFile(HashedFile[bytes]):
    @property
    def contents(self) -> bytes:
        assert self._contents is not None
        return self._contents


class HeaderFile(HashedFile[str]):
    @classmethod
    def _to_bytes(cls, contents: T) -> bytes:
        return b64decode(contents)

    @property
    def contents(self) -> str:
        assert self._contents is not None
        return b64encode(self._contents).decode('ascii')


@app.post('/recrypt_header')
async def recrypt_header(params: UserRecryptParams,
                         settings: Annotated[UserSettings, Depends(get_user_settings)],
                         request: Request) -> UserRecryptResponse:

    with open(settings.user_public_key_path, 'r') as user_public_key:
        client = request.state.client
        url = f'https://{settings.compute_host}:{settings.compute_port}/get_compute_key_info'
        payload = ComputeKeyInfoParams(crypt4gh_user_public_key=user_public_key.read())
        print(url)
        print(payload)
        response = await client.post(url, json=payload.dict())
        response.raise_for_status()

    key_info = parse_obj_as(ComputeKeyInfoResponse, response.json())

    compute_key_file = HashedBytesFile(settings.compute_keys_dir,
                                       key_info.crypt4gh_compute_public_key.encode('ascii'))
    compute_key_file.write_to_storage()

    in_header_file = HeaderFile(settings.headers_dir, params.crypt4gh_header)
    in_header_file.write_to_storage()
    out_header_file = HeaderFile(settings.headers_dir)

    try:
        run_in_subprocess(
            f'crypt4gh-recryptor recrypt '
            f'--encryption-key {compute_key_file.path} '
            f'-i {in_header_file.path} '
            f'-o {out_header_file.path} '
            f'--decryption-key {settings.user_private_key_path}',
            verbose=settings.dev_mode)
    except CalledProcessError as e:
        if e.returncode == 1:
            raise HTTPException(
                status_code=406,
                detail='The key header was not able to decode the header. '
                'Please make sure that the encrypted header is '
                "decryptable by the user's private key") from e
        else:
            raise e

    out_header_file.read_from_storage()

    return UserRecryptResponse(
        crypt4gh_header=out_header_file.contents,
        crypt4gh_compute_keypair_id=key_info.crypt4gh_compute_keypair_id,
        crypt4gh_compute_keypair_expiration_date=key_info.crypt4gh_compute_keypair_expiration_date,
    )
