"""`python -m modgudr.broker`: the daemon (re-executes under `-I`, then hardens)."""

from .daemon import entry

entry()
