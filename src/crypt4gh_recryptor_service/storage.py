from abc import abstractmethod
from base64 import b64decode, b64encode
from binascii import Error as BinasciiError
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
from pathlib import Path
import re
import tempfile
from typing import Generic, Mapping, Optional, TypeVar

from crypt4gh_recryptor_service.config import (ComputeSettings,
                                               DEFAULT_COMPUTE_KEY_ID_PREFIX,
                                               Settings)
from crypt4gh_recryptor_service.util import ensure_dirs
from crypt4gh_recryptor_service.validators import parse_iso_datetime, to_iso
from fastapi import HTTPException

T = TypeVar('T')

INDEX_DIR_NAME = 'index'
KEY_ID_ALLOWLIST = r'^[a-z0-9_]+$'

def is_valid_compute_key_id(key_id: str) -> bool:
    key_id_allowlist = rf'^{DEFAULT_COMPUTE_KEY_ID_PREFIX}[a-z0-9_]+$'
    return bool(re.fullmatch(key_id_allowlist, key_id))


def ensure_datetime(expiration_date: str | datetime) -> datetime:
    if isinstance(expiration_date, str):
        return parse_iso_datetime(expiration_date)
    return expiration_date


def timestamp_is_expired_or_near_expiry(
    settings: ComputeSettings,
    expiration_date: datetime | str,
) -> bool:
    return ensure_datetime(expiration_date) - datetime.now(timezone.utc) < timedelta(
        seconds=settings.compute_key_min_expiration_delta_req)


class HashedFile(Generic[T]):
    def __init__(self,
                 dir: Path,
                 content: Optional[T] = None,
                 filename: Optional[str] = None,
                 write_to_storage: bool = False):
        self.dir: Path = dir
        self._content: Optional[bytes] = self._to_bytes(content) if content else None

        self._rename_to_hash = False if filename else True

        if not filename:
            filename = self._content_sha256() if self._content else tempfile.mktemp(dir=self.dir)
        self._filename = filename

        if write_to_storage:
            self.write_to_storage()

    @classmethod
    def _to_bytes(cls, content: T) -> bytes:
        assert isinstance(content, bytes)
        return content

    @property
    @abstractmethod
    def content(self) -> T:
        ...

    def _content_sha256(self) -> str:
        assert self._content is not None
        return sha256(self._content).hexdigest()

    @property
    def path(self) -> Path:
        return self.dir.joinpath(self._filename)

    def write_to_storage(self):
        assert self._content is not None
        with open(self.path, 'wb') as hashed_file:
            hashed_file.write(self._content)
        self.path.chmod(mode=0o600)

    def read_from_storage(self):
        with open(self.path, 'rb') as hashed_file:
            self._content = hashed_file.read()
            if self._rename_to_hash and self._filename != self._content_sha256():
                self.path.rename(self.dir.joinpath(self._content_sha256()))


class HashedBytesFile(HashedFile[bytes]):
    @property
    def content(self) -> bytes:
        assert self._content is not None
        return self._content


class HashedStrFile(HashedFile[str]):
    @classmethod
    def _to_bytes(cls, content: str) -> bytes:
        return content.encode('utf8')

    @property
    def content(self) -> str:
        assert self._content is not None
        return self._content.decode('utf8')


class HeaderFile(HashedFile[str]):
    @classmethod
    def _to_bytes(cls, content: str) -> bytes:
        try:
            return b64decode(content)
        except ValueError as e:
            raise ValueError('Malformed or undecryptable crypt4gh_header') from e

    @property
    def content(self) -> str:
        assert self._content is not None
        return b64encode(self._content).decode('ascii')


class ComputeKeyFile(HashedStrFile):
    def __init__(self,
                 key_id_dir: Path,
                 content: Optional[str] = None,
                 public: bool = True,
                 write_to_storage: bool = False):

        filename = key_id_dir.name + ('.pub' if public else '.priv')
        super().__init__(key_id_dir, content, filename=filename, write_to_storage=write_to_storage)

    @property
    def key_id(self) -> str:
        key_id = self.path.parent.name
        assert is_valid_compute_key_id(key_id)
        return key_id

    @property
    def expiration_date(self) -> str:
        return self.path.parent.parent.name

    @property
    def user_hash(self) -> str:
        return self.path.parent.parent.parent.name


class ComputeKeypairFiles:
    def __init__(
        self,
        key_id_dir: Path,
        write_to_storage: bool = False,
    ) -> None:
        self.public_key_file = ComputeKeyFile(
            key_id_dir, public=True, write_to_storage=write_to_storage)
        self.private_key_file = ComputeKeyFile(
            key_id_dir, public=False, write_to_storage=write_to_storage)

    @classmethod
    def lookup_last_exp_key_id_dir_or_create_new(
        cls,
        settings: ComputeSettings,
        user_public_key_hash: str,
    ) -> Path:
        key_id_dir = None

        key_dir = settings.compute_keys_dir.joinpath(user_public_key_hash)
        if key_dir.exists():
            key_id_dir = cls._get_last_non_expired_key_id_dir_if_any(settings, key_dir)

        if not key_id_dir:
            key_id_dir = cls._create_new_key_id_dir(settings, key_dir)

        return key_id_dir

    @classmethod
    def lookup_key_id_dir_from_key_id(
        cls,
        settings: ComputeSettings,
        key_id: str,
    ) -> Path | None:
        if not is_valid_compute_key_id(key_id):
            raise ValueError('Malformed crypt4gh key_id: ' + key_id)

        for user_hash_dir in settings.compute_keys_dir.iterdir():
            if not user_hash_dir.is_dir() or user_hash_dir.name == INDEX_DIR_NAME:
                continue

            for expiration_dir in user_hash_dir.iterdir():
                if not expiration_dir.is_dir():
                    continue

                try:
                    ensure_datetime(expiration_dir.name)
                except ValueError:
                    continue

                candidate_key_id_dir = settings.compute_keys_dir.joinpath(
                    user_hash_dir.name,
                    expiration_dir.name,
                    key_id,
                )
                if candidate_key_id_dir.exists():
                    return candidate_key_id_dir

        return None

    @classmethod
    def _get_last_expiring_key_id_dir_or_create_new(
        cls,
        settings: ComputeSettings,
        key_dir: Path,
    ) -> Path:
        key_id_dir = None
        if key_dir.exists():
            key_id_dir = cls._get_last_non_expired_key_id_dir_if_any(settings, key_dir)

        if not key_id_dir:
            key_id_dir = cls._create_new_key_id_dir(settings, key_dir)

        return key_id_dir

    @classmethod
    def _create_new_key_id_dir(cls, settings: ComputeSettings, key_dir: Path) -> Path:
        exp_date_str = to_iso(
            datetime.now(timezone.utc)
            + timedelta(seconds=settings.compute_key_expiration_delta_secs))
        exp_id_dir = key_dir.joinpath(exp_date_str)
        ensure_dirs(exp_id_dir)
        key_id_dir = Path(tempfile.mkdtemp(prefix=settings.compute_key_id_prefix, dir=exp_id_dir))
        return key_id_dir

    @classmethod
    def _get_last_non_expired_key_id_dir_if_any(
        cls,
        settings: ComputeSettings,
        key_dir: Path,
    ) -> Path | None:
        key_id_dir = None
        exp_dates = [ensure_datetime(_.name) for _ in key_dir.iterdir()]
        exp_dates.sort()
        if exp_dates:
            last_exp_date = exp_dates[-1]
            if not timestamp_is_expired_or_near_expiry(settings, last_exp_date):
                last_exp_date_dir = key_dir.joinpath(to_iso(last_exp_date))
                for key_id_dir in last_exp_date_dir.iterdir():
                    break
        return key_id_dir

    def _get_attr_from_key_files_assume_same(self, attr_name: str) -> str:
        public_attr_val: str = getattr(self.public_key_file, attr_name)
        private_attr_val: str = getattr(self.private_key_file, attr_name)
        assert public_attr_val == private_attr_val
        assert public_attr_val is not None
        return public_attr_val

    @property
    def key_id(self) -> str:
        return self._get_attr_from_key_files_assume_same('key_id')

    @property
    def expiration_date(self) -> str:
        return self._get_attr_from_key_files_assume_same('expiration_date')

    @property
    def user_hash(self) -> str:
        return self._get_attr_from_key_files_assume_same('user_hash')

    def read_from_storage(self):
        self.public_key_file.read_from_storage()
        self.private_key_file.read_from_storage()


class ComputeKeyPairIndexFile(HashedFile[Mapping[str, str]]):
    USER_PUBLIC_KEY_HASH_KEY = 'user_public_key_hash'
    EXPIRATION_DATE_KEY = 'expiration_date'

    @classmethod
    def _to_bytes(cls, content: Mapping[str, str]) -> bytes:
        return json.dumps(content).encode('utf8')

    @property
    def content(self) -> Mapping[str, str]:
        assert self._content is not None
        return json.loads(self._content)

    def __init__(
        self,
        settings: ComputeSettings,
        compute_keypair: ComputeKeypairFiles,
        write_to_storage: bool = False,
    ):
        index_path = self.index_path(settings.compute_keys_dir, compute_keypair.key_id)
        ensure_dirs(index_path.parent)
        content = {
            self.USER_PUBLIC_KEY_HASH_KEY: compute_keypair.user_hash,
            self.EXPIRATION_DATE_KEY: compute_keypair.expiration_date,
        }
        super().__init__(
            index_path.parent,
            content=content,
            filename=index_path.name,
            write_to_storage=write_to_storage)

    @classmethod
    def index_dir(cls, compute_keys_dir: Path) -> Path:
        return compute_keys_dir.joinpath(INDEX_DIR_NAME)

    @classmethod
    def _index_shard(cls, key_id: str) -> str:
        key_id_suffix = key_id.split(':', 1)[1] if ':' in key_id else key_id
        return key_id_suffix[:2] if len(key_id_suffix) >= 2 else (key_id_suffix or '__')

    @classmethod
    def index_path(cls, compute_keys_dir: Path, key_id: str) -> Path:
        return cls.index_dir(compute_keys_dir).joinpath(cls._index_shard(key_id), f'{key_id}.json')

    @classmethod
    def delete_index_entry(cls, compute_keys_dir: Path, key_id: str) -> None:
        if not is_valid_compute_key_id(key_id):
            return

        index_path = cls.index_path(compute_keys_dir, key_id)
        if index_path.exists():
            index_path.unlink()

    @classmethod
    def lookup_compute_keypair_by_id(
        cls,
        settings: ComputeSettings,
        key_id: str,
    ) -> ComputeKeypairFiles | None:
        if not is_valid_compute_key_id(key_id):
            return None

        compute_keys_dir = settings.compute_keys_dir
        index_path = cls.index_path(compute_keys_dir, key_id)

        if index_path.exists():
            try:
                with open(index_path, 'r') as index_file:
                    metadata = json.load(index_file)
                user_hash = metadata[cls.USER_PUBLIC_KEY_HASH_KEY]
                expiration_date = metadata[cls.EXPIRATION_DATE_KEY]
                key_id_dir = settings.compute_keys_dir.joinpath(
                    user_hash,
                    to_iso(expiration_date),
                    key_id,
                )
                return ComputeKeypairFiles(key_id_dir)

            except (KeyError, ValueError, json.JSONDecodeError):
                pass

            cls.delete_index_entry(compute_keys_dir, key_id)
        else:
            if not compute_keys_dir.exists():
                return None

            key_id_dir = ComputeKeypairFiles.lookup_key_id_dir_from_key_id(settings, key_id)
            if key_id_dir:
                ComputeKeyPairIndexFile(
                    settings, ComputeKeypairFiles(key_id_dir), write_to_storage=True)
                return ComputeKeypairFiles(key_id_dir)

        return None


def header_file_from_payload(settings: Settings, crypt4gh_header: str) -> HeaderFile:
    try:
        return HeaderFile(settings.headers_dir, crypt4gh_header, write_to_storage=True)
    except (BinasciiError, ValueError) as e:
        raise HTTPException(
            status_code=422, detail='Malformed or undecryptable crypt4gh_header') from e
