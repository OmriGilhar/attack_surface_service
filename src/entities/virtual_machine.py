from .entity import Entity
from dataclasses import dataclass


@dataclass()
class VirtualMachine(Entity):
    """A virtual machine class"""
    name: str
    tags: list[str]
