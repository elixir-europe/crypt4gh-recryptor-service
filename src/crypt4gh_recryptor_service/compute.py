from datetime import datetime
from typing import Annotated, Union

from crypt4gh_recryptor_service.app import app, common_info
from crypt4gh_recryptor_service.config import ComputeSettings, get_compute_settings
from crypt4gh_recryptor_service.validators import to_iso
from fastapi import Depends
from pydantic import BaseModel, Field, validator


class ComputeRecryptParams(BaseModel):
    crypt4gh_header: str = Field(..., min_length=1)


class ComputeRecryptResponse(BaseModel):
    crypt4gh_header: str = Field(..., min_length=1)
    crypt4gh_compute_keypair_id: str = Field(..., min_length=1)
    crypt4gh_compute_keypair_expiration_date: Union[datetime, str]

    _to_iso = validator('crypt4gh_compute_keypair_expiration_date', allow_reuse=True)(to_iso)


@app.get('/info')
async def info(settings: Annotated[ComputeSettings, Depends(get_compute_settings)]) -> dict:
    return common_info(settings)


@app.post('/recrypt_header')
async def recrypt_header(params: ComputeRecryptParams) -> ComputeRecryptResponse:
    return ComputeRecryptResponse(
        crypt4gh_header='Y3J5cHQ0Z2gBAAAAAQAAAGwAAAAAAAAAwvnIV483knYvtjGVPNdxYOy0s8IMfh2kSSStkQT9Hx'
        'ZM4J0AQzlQJdAl2LiWsvDeO7kn21J9HhUSBoieyPguM5ZcSh6s6W8anu998UTklLw5x7jMu0BNdK4yqPRue9NNiGtt'
        'mw==',
        crypt4gh_compute_keypair_id='cn:b38ac81f',
        crypt4gh_compute_keypair_expiration_date='2023-06-30T12:15',
    )
