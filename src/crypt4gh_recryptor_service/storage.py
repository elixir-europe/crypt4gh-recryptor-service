from abc import abstractmethod
from base64 import b64decode, b64encode
from datetime import datetime, timedelta
from hashlib import sha256
import json
from pathlib import Path
import tempfile
from typing import Generic, Optional, TypeVar

from crypt4gh_recryptor_service.models import ComputeKeyInfo, ResolvedComputeKeypair
from crypt4gh_recryptor_service.util import ensure_dirs
from crypt4gh_recryptor_service.validators import to_iso

T = TypeVar('T', bytes, str)


class HashedFile(Generic[T]):
    def __init__(self,
                 dir: Path,
                 contents: Optional[T] = None,
                 filename: Optional[str] = None,
                 write_to_storage: bool = False):
        self._dir: Path = dir
        self._contents: Optional[bytes] = self._to_bytes(contents) if contents else None

        self._rename_to_hash = False if filename else True

        if not filename:
            filename = self.sha256 if self._contents else tempfile.mktemp(dir=self._dir)
        self._filename = filename

        if write_to_storage:
            self.write_to_storage()

    @classmethod
    def _to_bytes(cls, contents: T) -> bytes:
        assert isinstance(contents, bytes)
        return contents

    @property
    @abstractmethod
    def contents(self) -> T:
        ...

    @property
    def sha256(self):
        return sha256(self._contents).hexdigest()

    @property
    def path(self) -> Path:
        return self._dir.joinpath(self._filename)

    def write_to_storage(self):
        assert self._contents is not None
        with open(self.path, 'wb') as hashed_file:
            hashed_file.write(self._contents)
        self.path.chmod(mode=0o600)

    def read_from_storage(self):
        with open(self.path, 'rb') as hashed_file:
            self._contents = hashed_file.read()
            if self._rename_to_hash and self._filename != self.sha256:
                self.path.rename(self._dir.joinpath(self.sha256))


class HashedBytesFile(HashedFile[bytes]):
    @property
    def contents(self) -> bytes:
        assert self._contents is not None
        return self._contents


class HashedStrFile(HashedFile[str]):
    @classmethod
    def _to_bytes(cls, contents: str) -> bytes:
        return contents.encode('utf8')

    @property
    def contents(self) -> str:
        assert self._contents is not None
        return self._contents.decode('utf8')


class HeaderFile(HashedFile[str]):
    @classmethod
    def _to_bytes(cls, contents: str) -> bytes:
        return b64decode(contents)

    @property
    def contents(self) -> str:
        assert self._contents is not None
        return b64encode(self._contents).decode('ascii')


class ComputeKeyFile(HashedStrFile):
    def __init__(self,
                 dir: Path,
                 user_public_key_file: HashedStrFile,
                 compute_key_id_prefix: str,
                 compute_key_expiration_delta_secs: int,
                 contents: Optional[str] = None,
                 public: bool = True,
                 write_to_storage: bool = False):
        dir = dir.joinpath(user_public_key_file.path.name)

        key_id_dir = None
        if dir.exists():
            for exp_date_dir in dir.iterdir():
                exp_date = datetime.fromisoformat(exp_date_dir.name)
                if exp_date > datetime.now():
                    for key_id_dir in exp_date_dir.iterdir():
                        break
                    break

        if not key_id_dir:
            exp_date_str = to_iso(datetime.now()
                                  + timedelta(seconds=compute_key_expiration_delta_secs))
            exp_id_dir = dir.joinpath(exp_date_str)
            ensure_dirs(exp_id_dir)
            key_id_dir = Path(tempfile.mkdtemp(prefix=compute_key_id_prefix, dir=exp_id_dir))

        filename = key_id_dir.name + ('.pub' if public else '.priv')
        super().__init__(key_id_dir, contents, filename=filename, write_to_storage=write_to_storage)

    @property
    def key_id(self) -> str:
        return self.path.parent.name

    @property
    def expiration_date(self) -> str:
        return self.path.parent.parent.name

    @property
    def user_hash(self) -> str:
        return self.path.parent.parent.parent.name

    @classmethod
    def index_dir(cls, compute_keys_dir: Path) -> Path:
        return compute_keys_dir.joinpath('index')

    @classmethod
    def _index_shard(cls, key_id: str) -> str:
        key_id_suffix = key_id.split(':', 1)[1] if ':' in key_id else key_id
        return key_id_suffix[:2] if len(key_id_suffix) >= 2 else (key_id_suffix or '__')

    @classmethod
    def index_path(cls, compute_keys_dir: Path, key_id: str) -> Path:
        return cls.index_dir(compute_keys_dir).joinpath(cls._index_shard(key_id), f'{key_id}.json')

    @classmethod
    def write_index_entry(cls,
                          compute_keys_dir: Path,
                          key_id: str,
                          user_hash: str,
                          expiration: str) -> None:
        index_path = cls.index_path(compute_keys_dir, key_id)
        ensure_dirs(index_path.parent)

        tmp_path = index_path.with_suffix(index_path.suffix + '.tmp')
        payload = {'user_hash': user_hash, 'expiration': expiration}
        with open(tmp_path, 'w') as index_file:
            json.dump(payload, index_file)
        tmp_path.replace(index_path)

    @classmethod
    def delete_index_entry(cls, compute_keys_dir: Path, key_id: str) -> None:
        index_path = cls.index_path(compute_keys_dir, key_id)
        if index_path.exists():
            index_path.unlink()

    @classmethod
    def _resolve_paths_from_metadata(cls,
                                     compute_keys_dir: Path,
                                     key_id: str,
                                     user_hash: str,
                                     expiration: str) -> Optional[tuple[Path, Path]]:
        key_dir = compute_keys_dir.joinpath(user_hash, expiration, key_id)
        if not key_dir.is_dir():
            return None
        public_key_path = key_dir.joinpath(f'{key_id}.pub')
        private_key_path = key_dir.joinpath(f'{key_id}.priv')
        if not (public_key_path.exists() and private_key_path.exists()):
            return None

        return public_key_path, private_key_path

    @classmethod
    def lookup_by_key_id(
            cls,
            compute_keys_dir: Path,
            key_id: str) -> Optional[tuple[str, str, bool, Path, Path]]:
        index_path = cls.index_path(compute_keys_dir, key_id)
        now = datetime.now()

        if index_path.exists():
            try:
                with open(index_path, 'r') as index_file:
                    metadata = json.load(index_file)
                user_hash = metadata['user_hash']
                expiration = metadata['expiration']
                resolved_paths = cls._resolve_paths_from_metadata(
                    compute_keys_dir,
                    key_id,
                    user_hash,
                    expiration,
                )
                if resolved_paths is not None:
                    expiration_date = datetime.fromisoformat(expiration)
                    compute_public_key_path, compute_private_key_path = resolved_paths
                    return (
                        user_hash,
                        expiration,
                        expiration_date <= now,
                        compute_public_key_path,
                        compute_private_key_path,
                    )
            except (KeyError, ValueError, json.JSONDecodeError):
                pass

            cls.delete_index_entry(compute_keys_dir, key_id)

        if not compute_keys_dir.exists():
            return None

        expired_key_data = None
        for user_hash_dir in compute_keys_dir.iterdir():
            if not user_hash_dir.is_dir() or user_hash_dir.name == 'index':
                continue

            for expiration_dir in user_hash_dir.iterdir():
                if not expiration_dir.is_dir():
                    continue

                try:
                    expiration_date = datetime.fromisoformat(expiration_dir.name)
                except ValueError:
                    continue

                resolved_paths = cls._resolve_paths_from_metadata(
                    compute_keys_dir,
                    key_id,
                    user_hash_dir.name,
                    expiration_dir.name,
                )
                if resolved_paths is None:
                    continue

                compute_public_key_path, compute_private_key_path = resolved_paths

                cls.write_index_entry(
                    compute_keys_dir,
                    key_id,
                    user_hash_dir.name,
                    expiration_dir.name,
                )

                if expiration_date > now:
                    return (
                        user_hash_dir.name,
                        expiration_dir.name,
                        False,
                        compute_public_key_path,
                        compute_private_key_path,
                    )

                expired_key_data = (
                    user_hash_dir.name,
                    expiration_dir.name,
                    True,
                    compute_public_key_path,
                    compute_private_key_path,
                )

        return expired_key_data


def resolve_compute_keypair(
    compute_keys_dir: Path,
    user_keys_dir: Path,
    key_id: str,
) -> Optional[ResolvedComputeKeypair]:
    key_data = ComputeKeyFile.lookup_by_key_id(compute_keys_dir, key_id)
    if key_data is None:
        return None

    user_hash, expiration, is_expired, compute_public_key_path, compute_private_key_path = key_data

    user_public_key_path = user_keys_dir.joinpath(user_hash)
    if not user_public_key_path.exists():
        ComputeKeyFile.delete_index_entry(compute_keys_dir, key_id)
        return None

    key_info = ComputeKeyInfo(
        compute_keypair_id=key_id,
        compute_keypair_expiration_date=expiration,
    )
    return ResolvedComputeKeypair(
        key_info=key_info,
        is_expired=is_expired,
        compute_public_key_path=compute_public_key_path,
        compute_private_key_path=compute_private_key_path,
        user_public_key_path=user_public_key_path,
    )
