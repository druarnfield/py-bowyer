"""bowyer — pure-Python reference prototype of a TDS client for SQL Server.

PUBLIC API only: connect(), Connection, version, exceptions.
"""

from .prelogin import build_prelogin, parse_prelogin, parse_prelogin_encryption

__version__ = "0.1.0.dev0"
__all__ = ["build_prelogin", "parse_prelogin", "parse_prelogin_encryption"]
