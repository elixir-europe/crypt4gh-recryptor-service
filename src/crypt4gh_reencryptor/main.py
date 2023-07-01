from datetime import datetime
from typing import Union

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, validator, Field

app = FastAPI()

VERSION = '0.1.0'


class RecryptParams(BaseModel):
    crypt4gh_header: str = Field(..., min_length=1)


class RecryptResponse(BaseModel):
    crypt4gh_header: str = Field(..., min_length=1)
    crypt4gh_compute_keypair_id: str = Field(..., min_length=1)
    crypt4gh_compute_keypair_expiration_date: Union[datetime, str]

    @validator('crypt4gh_compute_keypair_expiration_date')
    def to_iso(cls, v):
        if isinstance(v, str):
            v = datetime(v)
        return v.isoformat(timespec='minutes')


@app.get("/info")
async def info():
    return {'name': 'crypt4gh_reencryptor', 'version': VERSION}


@app.post("/recrypt_header")
async def recrypt_header(params: RecryptParams) -> RecryptResponse:
    return RecryptResponse(
        crypt4gh_header= "Y3J5cHQ0Z2gBAAAAAQAAAGwAAAAAAAAAvVscAO1Vbvcyh+d2sZ2ZK++MObsAwccg81hC+kLytRWTtfOf8JnuOwo+ZbqCI41lxEcNNh3VxBSWtTL5m3YoYdnV1Sw+3ZBzvzaeYU7nMR+uVscBXdLStIMIlplvO6BAe1DwUg==",
        crypt4gh_compute_keypair_id= "cn:b38ac81f",
        crypt4gh_compute_keypair_expiration_date= "2023-06-30T12:15",
    )


origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["POST", "GET"],
    allow_headers=["*"],
    max_age=3600,
)
