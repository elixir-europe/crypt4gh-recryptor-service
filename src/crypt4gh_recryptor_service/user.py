from datetime import datetime
from typing import Annotated, Union

from crypt4gh_recryptor_service.app import app, common_info
from crypt4gh_recryptor_service.config import get_user_settings, UserSettings
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


@app.post('/recrypt_header')
async def recrypt_header(params: UserRecryptParams) -> UserRecryptResponse:
    return UserRecryptResponse(
        crypt4gh_header='Y3J5cHQ0Z2gBAAAAAQAAAGwAAAAAAAAAwvnIV483knYvtjGVPNdxYOy0s8IMfh2kSSStkQT9Hx'
        'ZM4J0AQzlQJdAl2LiWsvDeO7kn21J9HhUSBoieyPguM5ZcSh6s6W8anu998UTklLw5x7jMu0BNdK4yqPRue9NNiGtt'
        'mw==',
        crypt4gh_compute_keypair_id='cn:b38ac81f',
        crypt4gh_compute_keypair_expiration_date='2023-06-30T12:15',
    )
