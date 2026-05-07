from contextlib import asynccontextmanager
import ssl

from crypt4gh_recryptor_service.config import Settings, VERSION
from fastapi import FastAPI
import httpx
from starlette.middleware.cors import CORSMiddleware
import truststore


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Use the truststore of the local OS
    ctx = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

    # Initialise the Client on startup and add it to the state
    async with httpx.AsyncClient(verify=ctx) as client:
        yield {'client': client}
        # The Client closes on shutdown


app = FastAPI(lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=['*'],
    allow_credentials=True,
    allow_methods=['POST', 'GET'],
    allow_headers=['*'],
    max_age=3600,
)


def common_info(settings: Settings) -> dict:
    return {'name': 'crypt4gh-recryptor-service', 'version': VERSION, 'mode': settings.dev_mode}
