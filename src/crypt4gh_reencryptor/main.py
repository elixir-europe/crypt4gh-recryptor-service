from fastapi import FastAPI
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
    return [params.encrypted_header, params.reencrypt_public_key]
