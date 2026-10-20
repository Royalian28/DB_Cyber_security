"""Detector interface and registry.

To add a new attack type: subclass `Detector`, decorate it with `@register`,
and yield `Alert` objects from `detect()`. Nothing else needs to change; the
command line picks the new detector up automatically.
"""
from __future__ import annotations

import inspect
from abc import ABC, abstractmethod
from typing import Dict, Iterator, List, Type

from ..schema import Alert, AlertType


class Detector(ABC):
    name: str = ""                 # short id, also the command-line flag
    alert_type: AlertType          # which attack category this detector covers
    description: str = ""

    @abstractmethod
    def detect(self, path: str) -> Iterator[Alert]:
        """Read a log file (or folder) and yield normalised alerts."""


_REGISTRY: Dict[str, Type[Detector]] = {}


def register(cls: Type[Detector]) -> Type[Detector]:
    """Class decorator that makes a detector discoverable by name."""
    if not cls.name:
        raise ValueError(f"{cls.__name__} must define a non-empty 'name'")
    if cls.name in _REGISTRY:
        raise ValueError(f"Detector '{cls.name}' is already registered")
    _REGISTRY[cls.name] = cls
    return cls


def available() -> List[str]:
    return sorted(_REGISTRY)


def describe() -> Dict[str, str]:
    """Detector name -> one-line description, for help text."""
    return {name: _REGISTRY[name].description for name in available()}


def get_detector(name: str, **options) -> Detector:
    """Create a detector, passing only the options its constructor accepts."""
    try:
        cls = _REGISTRY[name]
    except KeyError:
        raise KeyError(f"Unknown detector '{name}'. Available: {available()}") from None
    accepted = inspect.signature(cls.__init__).parameters
    kwargs = {k: v for k, v in options.items() if k in accepted and v is not None}
    return cls(**kwargs)
