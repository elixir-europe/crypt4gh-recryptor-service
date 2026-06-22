import asyncio
from binascii import Error as BinasciiError
from typing import Annotated

from crypt4gh_recryptor_service.app import app, common_info
from crypt4gh_recryptor_service.config import ComputeSettings, get_compute_settings
from crypt4gh_recryptor_service.crypt import crypt4gh_generate_keypair, crypt4gh_recrypt_header
from crypt4gh_recryptor_service.models import (ComputeKeyInfoParams, ComputeKeyInfoResponse,
                                               ComputeRecryptHeaderToJobKeyParams,
                                               ComputeRecryptHeaderToJobKeyResponse,
                                               ComputeRecryptHeaderToUserKeyParams,
                                               ComputeRecryptHeaderToUserKeyResponse,
                                               ResolvedComputeKeypair)
from crypt4gh_recryptor_service.storage import (ComputeKeyFile, HashedStrFile, HeaderFile,
                                                resolve_compute_keypair)
from fastapi import Depends, HTTPException


_compute_key_lock = asyncio.Lock()


@app.get('/info')
async def info(settings: Annotated[ComputeSettings, Depends(get_compute_settings)]) -> dict:
    return common_info(settings)


@app.post('/get_compute_key_info')
async def get_compute_key_info(
    params: ComputeKeyInfoParams,
    settings: Annotated[ComputeSettings, Depends(get_compute_settings)],
) -> ComputeKeyInfoResponse:
    async with _compute_key_lock:
        user_public_key_file = HashedStrFile(
            settings.user_keys_dir, params.user_public_key, write_to_storage=True)
        compute_public_key_file = ComputeKeyFile(
            settings.compute_keys_dir,
            user_public_key_file,
            settings.compute_key_id_prefix,
            settings.compute_key_expiration_delta_secs,
            public=True)
        compute_private_key_file = ComputeKeyFile(
            settings.compute_keys_dir,
            user_public_key_file,
            settings.compute_key_id_prefix,
            settings.compute_key_expiration_delta_secs,
            public=False)

        existing_key_files: int = sum(
            1 for f in (compute_private_key_file, compute_public_key_file) if f.path.exists())

        if existing_key_files == 0:
            await crypt4gh_generate_keypair(
                compute_private_key_file.path,
                compute_public_key_file.path,
                settings.private_key_passphrase,
                settings.private_key_comment,
                verbose=settings.dev_mode)
        elif existing_key_files == 1:
            # TODO: Fix special case when key expires in between the checks of the public and private
            #       keys. Suggestion: allow a couple of retries.
            raise Exception('Only one of the compute node public/private keypair files exists!'
                            f' Key id: {compute_public_key_file.key_id}')
        else:
            assert existing_key_files == 2

        compute_public_key_file.read_from_storage()
        compute_private_key_file.read_from_storage()

        assert compute_public_key_file.key_id == compute_private_key_file.key_id

        return ComputeKeyInfoResponse(
            compute_public_key=compute_public_key_file.contents,
            compute_keypair_id=compute_public_key_file.key_id,
            compute_keypair_expiration_date=compute_public_key_file.expiration_date,
        )


def _resolve_compute_keypair_or_raise(key_id: str,
                                      settings: ComputeSettings) -> ResolvedComputeKeypair:
    keypair = resolve_compute_keypair(settings.compute_keys_dir, settings.user_keys_dir, key_id)
    if keypair is None:
        raise HTTPException(status_code=404, detail='Unknown crypt4gh_compute_keypair_id')
    if keypair.is_expired:
        raise HTTPException(status_code=410, detail='Expired crypt4gh_compute_keypair_id')
    return keypair


def _header_file_from_payload(settings: ComputeSettings, crypt4gh_header: str) -> HeaderFile:
    try:
        return HeaderFile(settings.headers_dir, crypt4gh_header, write_to_storage=True)
    except (BinasciiError, ValueError) as e:
        raise HTTPException(status_code=422, detail='Malformed or undecryptable crypt4gh_header') from e


@app.post('/recrypt_header_to_job_key')
async def recrypt_header_to_job_key(
    params: ComputeRecryptHeaderToJobKeyParams,
    settings: Annotated[ComputeSettings, Depends(get_compute_settings)],
) -> ComputeRecryptHeaderToJobKeyResponse:
    keypair = _resolve_compute_keypair_or_raise(
        params.compute_keypair_id, settings)
    in_header_file = _header_file_from_payload(settings, params.header)
    job_public_key_file = HashedStrFile(
        settings.compute_keys_dir, params.job_public_key, write_to_storage=True)

    out_header_file = await crypt4gh_recrypt_header(
        in_header_file,
        keypair.compute_private_key_path,
        job_public_key_file.path,
        verbose=settings.dev_mode)

    return ComputeRecryptHeaderToJobKeyResponse(
        header=out_header_file.contents,
        compute_public_key=keypair.compute_public_key_path.read_text(),
        compute_keypair_id=keypair.key_info.compute_keypair_id,
        compute_keypair_expiration_date=keypair.key_info.compute_keypair_expiration_date,
    )


@app.post('/recrypt_header_to_user_key')
async def recrypt_header_to_user_key(
    params: ComputeRecryptHeaderToUserKeyParams,
    settings: Annotated[ComputeSettings, Depends(get_compute_settings)],
) -> ComputeRecryptHeaderToUserKeyResponse:
    keypair = _resolve_compute_keypair_or_raise(
        params.compute_keypair_id, settings)
    in_header_file = _header_file_from_payload(settings, params.header)

    out_header_file = await crypt4gh_recrypt_header(
        in_header_file,
        keypair.compute_private_key_path,
        keypair.user_public_key_path,
        verbose=settings.dev_mode)

    return ComputeRecryptHeaderToUserKeyResponse(
        header=out_header_file.contents,
        compute_keypair_id=keypair.key_info.compute_keypair_id,
        compute_keypair_expiration_date=keypair.key_info.compute_keypair_expiration_date,
    )


# @app.post('/recrypt_header')
# async def recrypt_header(params: ComputeRecryptParams) -> ComputeRecryptResponse:
#     return ComputeRecryptResponse(
#         crypt4gh_header='Y3J5cHQ0Z2gBAAAAAQAAAGwAAAAAAAAAwvnIV483knYvtjGVPNdxYOy0s8IMfh2kSSStkQT9Hx'
#         'ZM4J0AQzlQJdAl2LiWsvDeO7kn21J9HhUSBoieyPguM5ZcSh6s6W8anu998UTklLw5x7jMu0BNdK4yqPRue9NNiGtt'
#         'mw==',
#         crypt4gh_compute_keypair_id='cn:b38ac81f',
#         crypt4gh_compute_keypair_expiration_date='2023-06-30T12:15',
#     )
