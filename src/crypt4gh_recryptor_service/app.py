from collections.abc import Sequence
from contextlib import asynccontextmanager
import ssl

from crypt4gh_recryptor_service.config import Settings, validate_allowed_origins, VERSION
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


def configure_user_cors(fastapi_app: FastAPI, allowed_origins: Sequence[str]) -> None:
    """Allow browser access to user mode only from explicitly configured origins."""
    origins = validate_allowed_origins(list(allowed_origins))
    if not origins:
        return

    fastapi_app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=False,
        allow_methods=['POST', 'GET'],
        allow_headers=['Content-Type'],
        max_age=3600,
    )


def common_info(settings: Settings) -> dict:
    return {'name': 'crypt4gh-recryptor-service', 'version': VERSION, 'mode': settings.dev_mode}
