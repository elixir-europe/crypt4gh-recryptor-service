from typing import Annotated

from crypt4gh_recryptor_service.app import app, common_info
from crypt4gh_recryptor_service.config import get_user_settings, UserSettings
from crypt4gh_recryptor_service.crypt import crypt4gh_recrypt_header
from crypt4gh_recryptor_service.exchange import fetch_compute_key_info
from crypt4gh_recryptor_service.models import UserRecryptParams, UserRecryptResponse
from crypt4gh_recryptor_service.storage import HashedStrFile, header_file_from_payload
from fastapi import Depends, Request


@app.get('/info')
async def info(settings: Annotated[UserSettings, Depends(get_user_settings)]) -> dict:
    return common_info(settings)


@app.post('/recrypt_header')
async def recrypt_header(params: UserRecryptParams,
                         settings: Annotated[UserSettings, Depends(get_user_settings)],
                         request: Request) -> UserRecryptResponse:

    in_header_file = header_file_from_payload(settings, params.header)

    key_info = await fetch_compute_key_info(request, settings)

    compute_public_key_file = HashedStrFile(
        settings.compute_keys_dir,
        key_info.compute_public_key,
        write_to_storage=True,
    )

    out_header_file = await crypt4gh_recrypt_header(
        in_header_file,
        settings.user_private_key_path,
        compute_public_key_file.path,
        verbose=settings.dev_mode)

    return UserRecryptResponse(
        header=out_header_file.content,  # type: ignore
        compute_keypair_id=key_info.compute_keypair_id,  # type: ignore
        compute_keypair_expiration_date=key_info.compute_keypair_expiration_date,  # type: ignore
    )
