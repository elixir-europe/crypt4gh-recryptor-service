# Crypt4GH Recryptor Service

## Installation

Install mkcert (https://github.com/FiloSottile/mkcert), e.g.:

`brew install mkcert`

Install crypt4gh-recryptor-service

`pip install crypt4gh-recryptor-service`

## Setup and run - User mode

`crypt4gh-recryptor-service user`

## Setup and run - Compute mode

`crypt4gh-recryptor-service compute`

## Compute-mode API

Compute mode exposes three header-focused routes:

- `POST /get_compute_key_info`
  - Request:
    - `crypt4gh_user_public_key` (string, full Crypt4GH user public key content)
  - Response:
    - `crypt4gh_compute_public_key`
    - `crypt4gh_compute_keypair_id`
    - `crypt4gh_compute_keypair_expiration_date`

- `POST /recrypt_header_to_job_key`
  - Request:
    - `crypt4gh_header` (base64-encoded Crypt4GH header bytes)
    - `crypt4gh_compute_keypair_id`
    - `crypt4gh_job_public_key` (string, full Crypt4GH job public key content)
  - Response:
    - `crypt4gh_header` (base64-encoded rewritten header)
    - `crypt4gh_compute_public_key`
    - `crypt4gh_compute_keypair_id`
    - `crypt4gh_compute_keypair_expiration_date`

- `POST /recrypt_header_to_user_key`
  - Request:
    - `crypt4gh_header` (base64-encoded Crypt4GH header bytes)
    - `crypt4gh_compute_keypair_id`
  - Response:
    - `crypt4gh_header` (base64-encoded rewritten header)
    - `crypt4gh_compute_keypair_id`
    - `crypt4gh_compute_keypair_expiration_date`

### Header-only contract

These routes are header-only in this slice: the service receives and returns Crypt4GH header bytes (base64-encoded) and key metadata; no full encrypted body payload is sent through these API endpoints.
