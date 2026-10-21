from .__version__ import __version__
from .extension import FlaskOPA
from .groups import groups_header_from_g, groups_header_from_request
from .opa_client import OPAClient

__all__ = [
    "__version__",
    "FlaskOPA",
    "OPAClient",
    "groups_header_from_g",
    "groups_header_from_request",
]
