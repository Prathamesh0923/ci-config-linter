"""YAML loading that keeps line numbers for mappings, keys and list items."""

from __future__ import annotations

import yaml


class LineDict(dict):
    """A dict that remembers its own line and the line of each key."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.line = 0
        self.key_lines: dict = {}

    def line_of(self, key, default=None) -> int:
        return self.key_lines.get(key, default if default is not None else self.line)


class LineList(list):
    """A list that remembers its own line and the line of each item."""

    def __init__(self, *args):
        super().__init__(*args)
        self.line = 0
        self.item_lines: list[int] = []


class _LineLoader(yaml.SafeLoader):
    pass


def _construct_mapping(loader: _LineLoader, node: yaml.MappingNode) -> LineDict:
    loader.flatten_mapping(node)
    result = LineDict()
    result.line = node.start_mark.line + 1
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=True)
        try:
            hash(key)
        except TypeError:
            key = str(key)
        result[key] = loader.construct_object(value_node, deep=True)
        result.key_lines[key] = key_node.start_mark.line + 1
    return result


def _construct_sequence(loader: _LineLoader, node: yaml.SequenceNode) -> LineList:
    result = LineList(loader.construct_object(child, deep=True) for child in node.value)
    result.line = node.start_mark.line + 1
    result.item_lines = [child.start_mark.line + 1 for child in node.value]
    return result


_LineLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping)
_LineLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_SEQUENCE_TAG, _construct_sequence)


def load_yaml(text: str):
    """Parse YAML text into LineDict / LineList structures.

    Raises yaml.YAMLError on invalid YAML.
    """
    return yaml.load(text, Loader=_LineLoader)  # noqa: S506 - SafeLoader subclass
