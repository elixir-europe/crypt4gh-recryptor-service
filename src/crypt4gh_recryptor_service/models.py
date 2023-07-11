from datetime import datetime
from typing import Union

from crypt4gh_recryptor_service.validators import to_iso
from pydantic import BaseModel, Field, validator


class ComputeKeyInfo(BaseModel):
    crypt4gh_compute_keypair_id: str = Field(..., min_length=1)
    crypt4gh_compute_keypair_expiration_date: Union[datetime, str]

    _to_iso = validator('crypt4gh_compute_keypair_expiration_date', allow_reuse=True)(to_iso)


class UserRecryptParams(BaseModel):
    crypt4gh_header: str = Field(..., min_length=1)


class UserRecryptResponse(ComputeKeyInfo):
    crypt4gh_header: str = Field(..., min_length=1)


class ComputeKeyInfoParams(BaseModel):
    crypt4gh_user_public_key: str = Field(..., min_length=1)


class ComputeKeyInfoResponse(ComputeKeyInfo):
    crypt4gh_compute_public_key: str = Field(..., min_length=1)


# class ComputeRecryptParams(BaseModel):
#     crypt4gh_header: str = Field(..., min_length=1)
#
#
# class ComputeRecryptResponse(ComputeKeyInfo):
#     crypt4gh_header: str = Field(..., min_length=1)
