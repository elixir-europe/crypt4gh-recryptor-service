from datetime import datetime
from subprocess import CalledProcessError
from typing import Annotated, Union

from crypt4gh_recryptor_service.app import app, common_info
from crypt4gh_recryptor_service.compute import ComputeKeyInfoParams, ComputeKeyInfoResponse
from crypt4gh_recryptor_service.config import get_user_settings, UserSettings
from crypt4gh_recryptor_service.storage import HashedBytesFile, HeaderFile
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


@app.post('/recrypt_header')
async def recrypt_header(params: UserRecryptParams,
                         settings: Annotated[UserSettings, Depends(get_user_settings)],
                         request: Request) -> UserRecryptResponse:

    with open(settings.user_public_key_path, 'r') as user_public_key:
        client = request.state.client
        url = f'https://{settings.compute_host}:{settings.compute_port}/get_compute_key_info'
        payload = ComputeKeyInfoParams(crypt4gh_user_public_key=user_public_key.read())
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
