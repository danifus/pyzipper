import sys

from .zipfile import *  # noqa: F401, F403
from .zipfile_aes import AESZipFile, WZ_AES  # noqa: F401
from .__version__ import __version__  # noqa: F401

if sys.version_info >= (3, 8):
    from ._path import Path  # noqa: F401
