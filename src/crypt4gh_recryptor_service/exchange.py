from crypt4gh_recryptor_service.models import ComputeKeyInfoParams, ComputeKeyInfoResponse
from pydantic import TypeAdapter


async def fetch_compute_key_info(request, settings):
    with open(settings.user_public_key_path, 'r') as user_public_key:
        client = request.state.client

        url = f'https://{settings.compute_host}:{settings.compute_port}/get_compute_key_info'
        payload = ComputeKeyInfoParams(user_public_key=user_public_key.read())

        response = await client.post(url, json=payload.model_dump(by_alias=True))
        response.raise_for_status()

    return TypeAdapter(ComputeKeyInfoResponse).validate_python(response.json())
