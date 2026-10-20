"""LockHTML - PIN-protect and one-time-view HTML files.

Encrypts any HTML document with AES-256-GCM under a key derived from a PIN,
producing a single self-contained .html file that asks for the PIN in the
browser and can be configured to expire after a single view.
"""

__version__ = "2.0.0"
__author__ = "Dr Sohil Momin"
__license__ = "MIT"

__all__ = ["__version__"]
