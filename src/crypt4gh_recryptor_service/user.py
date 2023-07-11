from typing import Annotated

from crypt4gh_recryptor_service.app import app, common_info
from crypt4gh_recryptor_service.config import get_user_settings, UserSettings
from crypt4gh_recryptor_service.crypt import crypt4gh_recrypt_header
from crypt4gh_recryptor_service.exchange import fetch_compute_key_info
from crypt4gh_recryptor_service.models import UserRecryptParams, UserRecryptResponse
from crypt4gh_recryptor_service.storage import HashedStrFile, HeaderFile
from fastapi import Depends, Request


@app.get('/info')
async def info(settings: Annotated[UserSettings, Depends(get_user_settings)]) -> dict:
    return common_info(settings)


@app.post('/recrypt_header')
async def recrypt_header(params: UserRecryptParams,
                         settings: Annotated[UserSettings, Depends(get_user_settings)],
                         request: Request) -> UserRecryptResponse:

    key_info = await fetch_compute_key_info(request, settings)

    in_header_file = HeaderFile(
        settings.headers_dir,
        params.crypt4gh_header,
        write_to_storage=True,
    )
    compute_public_key_file = HashedStrFile(
        settings.compute_keys_dir,
        key_info.crypt4gh_compute_public_key,
        write_to_storage=True,
    )

    out_header_file = await crypt4gh_recrypt_header(
        in_header_file,
        compute_public_key_file,
        settings.user_private_key_path,
        verbose=settings.dev_mode)

    return UserRecryptResponse(
        crypt4gh_header=out_header_file.contents,
        crypt4gh_compute_keypair_id=key_info.crypt4gh_compute_keypair_id,
        crypt4gh_compute_keypair_expiration_date=key_info.crypt4gh_compute_keypair_expiration_date,
    )
