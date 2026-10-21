"""Strict YAML: PyYAML's SafeLoader that raises on duplicate mapping keys (M10)."""

from __future__ import annotations

from collections.abc import Hashable
from typing import cast

import yaml
from yaml.nodes import MappingNode


class StrictYamlError(Exception):
    """A YAML file that cannot be read as strict YAML."""

    def __init__(self, file: str, line: int | None, key: str | None, message: str) -> None:
        self.file = file
        self.line = line
        self.key = key
        self.message = message
        where = file if line is None else f"{file}:{line}"
        super().__init__(f"{where}: {message}")


class _StrictLoader(yaml.SafeLoader):
    def construct_mapping(self, node: MappingNode, deep: bool = False) -> dict[Hashable, object]:
        self.flatten_mapping(node)
        seen: set[object] = set()
        for key_node, _ in node.value:
            key = self.construct_object(key_node, deep=True)  # pyright: ignore[reportUnknownMemberType]
            try:
                duplicate = key in seen
            except TypeError:
                # An unhashable key: SafeLoader reports it with its own error below.
                continue
            if duplicate:
                raise StrictYamlError(
                    getattr(self, "name", "<yaml>"),
                    key_node.start_mark.line + 1,
                    str(key),
                    f"duplicate key {key!r}",
                )
            seen.add(key)
        return cast(
            "dict[Hashable, object]",
            super().construct_mapping(node, deep=deep),  # pyright: ignore[reportUnknownMemberType]
        )


def load_strict(text: str, file: str) -> object:
    """Parse one YAML document. Duplicate keys and syntax errors raise StrictYamlError."""
    loader = _StrictLoader(text)
    loader.name = file
    try:
        return loader.get_single_data()  # pyright: ignore[reportUnknownMemberType]
    except StrictYamlError:
        raise
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        line = None if mark is None else int(mark.line) + 1
        problem = getattr(exc, "problem", None) or str(exc)
        raise StrictYamlError(file, line, None, f"YAML syntax error: {problem}") from exc
    finally:
        loader.dispose()
