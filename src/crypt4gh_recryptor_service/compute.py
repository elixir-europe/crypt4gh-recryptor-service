from typing import Annotated

from crypt4gh_recryptor_service.app import app, common_info
from crypt4gh_recryptor_service.config import ComputeSettings, get_compute_settings
from crypt4gh_recryptor_service.models import ComputeKeyInfoParams, ComputeKeyInfoResponse
from fastapi import Depends


@app.get('/info')
async def info(settings: Annotated[ComputeSettings, Depends(get_compute_settings)]) -> dict:
    return common_info(settings)


@app.post('/get_compute_key_info')
async def get_compute_key_info(params: ComputeKeyInfoParams) -> ComputeKeyInfoResponse:
    # user_public_key = params.crypt4gh_user_public_key

    return ComputeKeyInfoResponse(
        crypt4gh_compute_public_key='-----BEGIN CRYPT4GH PUBLIC KEY-----\n'
        '2fppz5Q7QMHVLm3eCJp2+sbjCGyDwKktjArAa+Qe9n4=\n'
        '-----END CRYPT4GH PUBLIC KEY-----\n',
        crypt4gh_compute_keypair_id='cn:b38ac81f',
        crypt4gh_compute_keypair_expiration_date='2023-06-30T12:15',
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
