from abc import abstractmethod
from base64 import b64decode, b64encode
from datetime import datetime, timedelta
from hashlib import sha256
from pathlib import Path
import tempfile
from typing import Generic, Optional, TypeVar

from crypt4gh_recryptor_service.util import ensure_dirs
from crypt4gh_recryptor_service.validators import to_iso

T = TypeVar('T', bytes, str)


class HashedFile(Generic[T]):
    def __init__(self, dir: Path, contents: Optional[T] = None, write_to_storage: bool = False):
        self._dir: Path = dir
        self._contents: Optional[bytes] = self._to_bytes(contents) if contents else None
        self._filename: str = self.sha256 if self._contents else tempfile.mktemp(dir=self._dir)
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
            if self._filename != self.sha256:
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

        super().__init__(key_id_dir, contents, write_to_storage)

    @property
    def key_id(self) -> str:
        return self.path.parent.name

    @property
    def expiration_date(self) -> str:
        return self.path.parent.parent.name
