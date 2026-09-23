"""
yaml_safe.py — a `yaml.SafeLoader` with two of PyYAML's implicit
scalar resolvers narrowed, used for the one place this service parses
attacker-reachable YAML: the ---GATEKEEPER-REQUEST--- block
(app/request_parser.py).

PyYAML 1.1 resolves *unquoted* scalars to non-string types more eagerly
than a requester would expect:

  - `title: Off` / `location: No` / `max_results: yes` resolve to Python
    `bool`, not `str` -- app/policy.py's numeric fields already guard
    against this (`isinstance(x, int) and not isinstance(x, bool)`), so
    a bool there is correctly denied either way, but a STRING field
    (title, location, query, ...) only checks `isinstance(x, str)`, so
    a legitimate value that happens to look like a YAML boolean word is
    wrongly denied as `invalid_params`.
  - `start_time: 9:00` (unquoted) resolves via YAML 1.1's sexagesimal
    (base-60) int form to the integer 540, not the string "9:00" --
    same wrong-denial outcome for a perfectly normal time.

Both failure modes deny the request (this service's validators reject
non-string values outright), so neither is a security hole -- they're
usability bugs: a well-formed request from Instinct's point of view
gets an `invalid_params` reply for a value it never asked to be
retyped. Fixing it here, once, is simpler and more robust than asking
Instinct to remember to quote every value that happens to collide with
a YAML keyword.

This loader removes the bool resolver entirely and keeps the int
resolver's binary/octal/decimal/hex forms while dropping only the
sexagesimal (colon-separated) alternative. No other type's parsing
changes: `max_results: 5` still resolves to `int(5)`, `duration_minutes:
30` still resolves to `int(30)`, etc. -- this narrows *ambiguous*
scalar-to-non-string coercion, it does not turn every field into a
string.
"""
from __future__ import annotations

import re

import yaml


class NoCoerceSafeLoader(yaml.SafeLoader):
    """See module docstring. A private subclass so this narrowing never
    leaks into any other `yaml.safe_load`/`yaml.SafeLoader` use in this
    codebase or a dependency."""


_INT_RE = re.compile(
    r"""^(?:[-+]?0b[0-1_]+
        |[-+]?0[0-7_]+
        |[-+]?(?:0|[1-9][0-9_]*)
        |[-+]?0x[0-9a-fA-F_]+)$""",
    re.X,
)

NoCoerceSafeLoader.yaml_implicit_resolvers = {
    first_char: [
        (tag, _INT_RE) if tag == "tag:yaml.org,2002:int" else (tag, regex)
        for tag, regex in resolvers
        if tag != "tag:yaml.org,2002:bool"
    ]
    for first_char, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
}


def safe_load_no_coerce(text: str):
    """`yaml.safe_load`, but see module docstring: unquoted
    yes/no/true/false/on/off and H:MM-shaped scalars stay strings
    instead of silently becoming bool/int."""
    return yaml.load(text, Loader=NoCoerceSafeLoader)
