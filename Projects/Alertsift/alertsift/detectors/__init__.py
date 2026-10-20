"""Detector plug-ins. Importing this package registers every built-in detector."""
from . import auth, c2, phishing, portscan, web
from .base import Detector, available, describe, get_detector, register

__all__ = [
    "Detector", "available", "describe", "get_detector", "register",
    "auth", "c2", "phishing", "portscan", "web",
]
