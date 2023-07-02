from fastapi import FastAPI
from starlette.middleware.cors import CORSMiddleware

from crypt4gh_recryptor_service.config import VERSION, Settings

app = FastAPI()


origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["POST", "GET"],
    allow_headers=["*"],
    max_age=3600,
)

def common_info(settings: Settings) -> dict:
    return {'name': 'crypt4gh-recryptor-service', 'version': VERSION, 'mode': settings.dev_mode}
