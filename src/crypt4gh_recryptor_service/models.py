from datetime import datetime
from pathlib import Path
from typing import Union

from crypt4gh_recryptor_service.validators import to_iso
from pydantic import BaseModel, Field, validator


class ApiModel(BaseModel):
    class Config:
        allow_population_by_field_name = True


class ComputeKeyInfo(ApiModel):
    compute_keypair_id: str = Field(..., min_length=1, alias='crypt4gh_compute_keypair_id')
    compute_keypair_expiration_date: Union[datetime, str] = Field(
        ..., alias='crypt4gh_compute_keypair_expiration_date')

    _to_iso = validator('compute_keypair_expiration_date', allow_reuse=True)(to_iso)


class UserRecryptParams(ApiModel):
    header: str = Field(..., min_length=1, alias='crypt4gh_header')


class UserRecryptResponse(ComputeKeyInfo):
    header: str = Field(..., min_length=1, alias='crypt4gh_header')


class ComputeKeyInfoParams(ApiModel):
    user_public_key: str = Field(..., min_length=1, alias='crypt4gh_user_public_key')


class ComputeKeyInfoResponse(ComputeKeyInfo):
    compute_public_key: str = Field(..., min_length=1, alias='crypt4gh_compute_public_key')


class ComputeRecryptHeaderToJobKeyParams(ApiModel):
    header: str = Field(..., min_length=1, alias='crypt4gh_header')
    compute_keypair_id: str = Field(..., min_length=1, alias='crypt4gh_compute_keypair_id')
    job_public_key: str = Field(..., min_length=1, alias='crypt4gh_job_public_key')


class ComputeRecryptHeaderToJobKeyResponse(ComputeKeyInfoResponse):
    header: str = Field(..., min_length=1, alias='crypt4gh_header')


class ComputeRecryptHeaderToUserKeyParams(ApiModel):
    header: str = Field(..., min_length=1, alias='crypt4gh_header')
    compute_keypair_id: str = Field(..., min_length=1, alias='crypt4gh_compute_keypair_id')


class ComputeRecryptHeaderToUserKeyResponse(ComputeKeyInfo):
    header: str = Field(..., min_length=1, alias='crypt4gh_header')


class ResolvedComputeKeypair(ApiModel):
    key_info: ComputeKeyInfo
    is_expired: bool
    compute_public_key_path: Path
    compute_private_key_path: Path
    user_public_key_path: Path
