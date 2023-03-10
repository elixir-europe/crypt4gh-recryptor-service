from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI()

VERSION = '0.1.0'


class ReencryptParams(BaseModel):
    encrypted_header: str
    reencrypt_public_key: str


@app.get("/info")
async def info():
    return {'name': 'crypt4gh_reencryptor', 'version': VERSION}


@app.post("/reencrypt_header")
async def reencrypt_header(params: ReencryptParams):
    return ['This is from my local laptop', params.encrypted_header, params.reencrypt_public_key]


origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["POST", "GET"],
    allow_headers=["*"],
    max_age=3600,
)
