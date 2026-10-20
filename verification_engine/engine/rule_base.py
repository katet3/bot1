# verification_engine/engine/rule_base.py

from abc import ABC, abstractmethod


class Rule(ABC):

    name: str = "abstract_rule"

    def __init__(self, severity="ERROR"):
        self.severity = severity

    @abstractmethod
    def check(self, cfg, context):
        """
        Returns list[VerificationError]
        """
        pass