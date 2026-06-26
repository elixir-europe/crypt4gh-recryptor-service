import asyncio
from typing import Annotated

from crypt4gh_recryptor_service.app import app, common_info
from crypt4gh_recryptor_service.config import ComputeSettings, get_compute_settings
from crypt4gh_recryptor_service.crypt import crypt4gh_generate_keypair, crypt4gh_recrypt_header
from crypt4gh_recryptor_service.models import (ComputeKeyInfoParams,
                                               ComputeKeyInfoResponse,
                                               ComputeRecryptHeaderToJobKeyParams,
                                               ComputeRecryptHeaderToJobKeyResponse,
                                               ComputeRecryptHeaderToUserKeyParams,
                                               ComputeRecryptHeaderToUserKeyResponse)
from crypt4gh_recryptor_service.storage import (ComputeKeypairFiles,
                                                ComputeKeyPairIndexFile,
                                                HashedStrFile,
                                                header_file_from_payload,
                                                timestamp_is_expired_or_near_expiry)
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
        key_id_dir = ComputeKeypairFiles.lookup_last_exp_key_id_dir_or_create_new(
            settings,
            user_public_key_file.path.name,
        )
        compute_keypair = ComputeKeypairFiles(key_id_dir)

        existing_key_files: int = sum(1 for f in (compute_keypair.private_key_file,
                                                  compute_keypair.public_key_file)
                                      if f.path.exists())

        if existing_key_files == 0:
            await crypt4gh_generate_keypair(
                compute_keypair.private_key_file.path,
                compute_keypair.public_key_file.path,
                settings.private_key_passphrase,
                settings.private_key_comment,
                verbose=settings.dev_mode)
        elif existing_key_files == 1:
            # TODO: Fix special case when key expires in between the checks of the public and
            #       private keys. Suggestion: allow a couple of retries.
            raise Exception('Only one of the compute node public/private keypair files exists!'
                            f' Key id: {compute_keypair.key_id}')
        else:
            assert existing_key_files == 2

        compute_keypair.read_from_storage()

        ComputeKeyPairIndexFile(settings, compute_keypair, write_to_storage=True)

        return ComputeKeyInfoResponse(  # type: ignore
            compute_public_key=compute_keypair.public_key_file.contents,  # type: ignore
            compute_keypair_id=compute_keypair.key_id,  # type: ignore
            compute_keypair_expiration_date=compute_keypair.expiration_date,  # type: ignore
        )


def _lookup_compute_keypair_by_id_or_raise(
    settings: ComputeSettings,
    key_id: str,
) -> ComputeKeypairFiles:
    keypair = ComputeKeyPairIndexFile.lookup_compute_keypair_by_id(settings, key_id)
    if keypair is None:
        raise HTTPException(status_code=404, detail='Unknown crypt4gh_compute_keypair_id')
    if timestamp_is_expired_or_near_expiry(settings, keypair.expiration_date):
        raise HTTPException(status_code=410, detail='Expired crypt4gh_compute_keypair_id')
    return keypair


@app.post('/recrypt_header_to_job_key')
async def recrypt_header_to_job_key(
    params: ComputeRecryptHeaderToJobKeyParams,
    settings: Annotated[ComputeSettings, Depends(get_compute_settings)],
) -> ComputeRecryptHeaderToJobKeyResponse:
    compute_keypair = _lookup_compute_keypair_by_id_or_raise(settings, params.compute_keypair_id)
    in_header_file = header_file_from_payload(settings, params.header)
    job_public_key_file = HashedStrFile(
        settings.compute_keys_dir, params.job_public_key, write_to_storage=True)

    out_header_file = await crypt4gh_recrypt_header(
        in_header_file,
        compute_keypair.private_key_file.path,
        job_public_key_file.path,
        decryption_passphrase=settings.private_key_passphrase,
        verbose=settings.dev_mode)

    return ComputeRecryptHeaderToJobKeyResponse(  # type: ignore
        header=out_header_file.contents,  # type: ignore
        compute_public_key=compute_keypair.public_key_file.path.read_text(),  # type: ignore
        compute_keypair_id=compute_keypair.key_id,  # type: ignore
        compute_keypair_expiration_date=compute_keypair.expiration_date,  # type: ignore
    )


@app.post('/recrypt_header_to_user_key')
async def recrypt_header_to_user_key(
    params: ComputeRecryptHeaderToUserKeyParams,
    settings: Annotated[ComputeSettings, Depends(get_compute_settings)],
) -> ComputeRecryptHeaderToUserKeyResponse:
    compute_keypair = _lookup_compute_keypair_by_id_or_raise(settings, params.compute_keypair_id)
    in_header_file = header_file_from_payload(settings, params.header)

    user_public_key_path = settings.user_keys_dir.joinpath(compute_keypair.user_hash)
    out_header_file = await crypt4gh_recrypt_header(
        in_header_file,
        compute_keypair.private_key_file.path,
        user_public_key_path,
        decryption_passphrase=settings.private_key_passphrase,
        verbose=settings.dev_mode)

    return ComputeRecryptHeaderToUserKeyResponse(
        header=out_header_file.contents,  # type: ignore
        compute_keypair_id=compute_keypair.key_id,  # type: ignore
        compute_keypair_expiration_date=compute_keypair.expiration_date,  # type: ignore
    )
