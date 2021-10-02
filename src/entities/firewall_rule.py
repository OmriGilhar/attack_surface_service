from .entity import Entity
from dataclasses import dataclass


@dataclass()
class FirewallRule(Entity):
    """A firewall rule class"""
    source_tag: str
    dest_tag: str
