"""Generate Rust structure and enumeration definitions from YANG modules.

The plug-in groups types into Rust modules that match their source YANG
modules. Thus, ietf-keystore groupings produce ``keystore::InlineDefinition``
instead of a flattened ``TacacsPlusServerCertificateInlineDefinition``.

Usage:
    pyang --plugindir <dir-containing-this-file> -f rust \\
          -p <search-paths> module.yang
"""

from __future__ import annotations

from collections import OrderedDict
from pathlib import Path
from typing import TextIO
import tomllib

from pyang import plugin


def pyang_plugin_init():
    plugin.register_plugin(YangToRustPlugin())


# ---------------------------------------------------------------------------
# Map YANG types to Rust types.
# ---------------------------------------------------------------------------

_ENUM_SENTINEL = "__ENUM__"
_BITS_SENTINEL = "__BITS__"
_IDENTITYREF_SENTINEL = "__IDENTITYREF__"
_BINARY_SENTINEL = "__BINARY__"

_YANG_TO_RUST = {
    "string": "String",
    "boolean": "bool",
    "empty": "bool",
    "uint8": "u8",
    "uint16": "u16",
    "uint32": "u32",
    "uint64": "u64",
    "int8": "i8",
    "int16": "i16",
    "int32": "i32",
    "int64": "i64",
    "binary": _BINARY_SENTINEL,
    "identityref": _IDENTITYREF_SENTINEL,
    "union": "String",
    "decimal64": "f64",
    "instance-identifier": "String",
    # These common types come from ietf-yang-types and ietf-inet-types.
    "date-and-time": "String",
    "counter64": "u64",
    "counter32": "u32",
    "gauge64": "u64",
    "gauge32": "u32",
    "ip-address": "String",
    "ipv4-address": "String",
    "ipv6-address": "String",
    "ip-prefix": "String",
    "domain-name": "String",
    "host": "String",
    "port-number": "u16",
    "uri": "String",
    "interface-ref": "String",
}

_RUST_KEYWORDS = frozenset({
    "as", "break", "const", "continue", "crate", "else", "enum", "extern",
    "false", "fn", "for", "if", "impl", "in", "let", "loop", "match", "mod",
    "move", "mut", "pub", "ref", "return", "self", "static", "struct", "super",
    "trait", "true", "type", "unsafe", "use", "where", "while", "async",
    "await", "dyn", "abstract", "become", "box", "do", "final", "macro",
    "override", "priv", "try", "typeof", "unsized", "virtual", "yield",
})

# Map YANG module names to Rust module names.
_MODULE_MAP = {
    "ietf-crypto-types": "crypto_types",
    "ietf-keystore": "keystore",
    "ietf-truststore": "truststore",
    "ietf-tls-common": "tls_common",
    "ietf-tls-client": "tls_client",
    "ietf-system-tacacs-plus": "tacacs_plus",
    "ietf-netconf-acm": "nacm",
    "tacacsrs": "tacacsrs",
}

_PROJECT_MODULE_NAMES = frozenset({"tacacsrs"})
_PROJECT_MODULE_PREFIX = "tacacsrs-"

# Skip modules that contain only primitive types and typedefs.
_SKIP_MODULES = frozenset({
    "ietf-inet-types", "ietf-yang-types", "ietf-system",
    "ietf-interfaces", "ietf-network-instance",
})

SECRET_FIELDS_PATH = Path(__file__).resolve().parent.parent / "secret-fields.toml"


class SecretFieldRule:
    __slots__ = ("module", "leaf", "kind", "expected_matches", "actual_matches")

    def __init__(self, module: str, leaf: str, kind: str, expected_matches: int):
        self.module = module
        self.leaf = leaf
        self.kind = kind
        self.expected_matches = expected_matches
        self.actual_matches = 0


class SecretFieldManifest:
    """Store fail-closed annotations for YANG leaves that contain secret values."""

    def __init__(self, rules: dict[tuple[str, str], SecretFieldRule]):
        self._rules = rules

    @classmethod
    def load(cls, path: Path) -> "SecretFieldManifest":
        try:
            document = tomllib.loads(path.read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError) as error:
            raise RuntimeError(f"The plug-in did not load the secret-field manifest {path}") from error

        entries = document.get("secret", [])
        if not isinstance(entries, list):
            raise RuntimeError("The secret-field manifest value 'secret' must be an array of tables")

        rules: dict[tuple[str, str], SecretFieldRule] = {}
        for index, entry in enumerate(entries):
            if not isinstance(entry, dict):
                raise RuntimeError(f"Secret-field annotation {index} must be a table")
            module = entry.get("module")
            leaf = entry.get("leaf")
            kind = entry.get("kind")
            expected_matches = entry.get("expected_matches")
            if not isinstance(module, str) or not module:
                raise RuntimeError(f"Secret-field annotation {index} requires a module")
            if not isinstance(leaf, str) or not leaf:
                raise RuntimeError(f"Secret-field annotation {index} requires a leaf")
            if kind not in ("string", "binary"):
                raise RuntimeError(
                    f"Secret-field annotation {module}:{leaf} has unsupported kind {kind!r}"
                )
            if not isinstance(expected_matches, int) or expected_matches < 1:
                raise RuntimeError(
                    f"Secret-field annotation {module}:{leaf} requires a positive expected_matches value"
                )
            identity = (module, leaf)
            if identity in rules:
                raise RuntimeError(
                    f"Duplicate secret-field annotation for {module}:{leaf}"
                )
            rules[identity] = SecretFieldRule(module, leaf, kind, expected_matches)
        return cls(rules)

    def match(self, module: str, leaf: str, rust_type: str) -> str | None:
        rule = self._rules.get((module, leaf))
        if rule is None:
            return None
        expected_type = "String" if rule.kind == "string" else "Vec<u8>"
        if rust_type != expected_type:
            raise RuntimeError(
                f"Secret-field annotation {module}:{leaf} of kind {rule.kind} "
                f"requires Rust type {expected_type}. The type was {rust_type}."
            )
        rule.actual_matches += 1
        return rule.kind

    def verify_complete(self) -> None:
        for rule in self._rules.values():
            if rule.actual_matches != rule.expected_matches:
                raise RuntimeError(
                    f"Secret-field annotation {rule.module}:{rule.leaf} matched "
                    f"{rule.actual_matches} field(s). The expected count is {rule.expected_matches}."
                )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _yang_to_pascal(name: str) -> str:
    return "".join(part.capitalize() for part in name.split("-"))


def _yang_to_snake(name: str) -> str:
    return name.replace("-", "_")


def _needs_rename(yang_name: str) -> bool:
    return "-" in yang_name


def _is_config_false(stmt) -> bool:
    config = stmt.search_one("config")
    return config is not None and config.arg == "false"


def _should_skip(stmt) -> bool:
    if _is_config_false(stmt):
        return True
    if stmt.keyword in ("notification", "rpc", "action"):
        return True
    return False


def _get_children(stmt):
    if not hasattr(stmt, "i_children"):
        return []
    return [ch for ch in stmt.i_children if not _should_skip(ch)]


def _is_mandatory(stmt) -> bool:
    m = stmt.search_one("mandatory")
    return m is not None and m.arg == "true"


def _safe_name(snake: str) -> str:
    if snake in _RUST_KEYWORDS:
        return f"r#{snake}"
    return snake


def _resolve_type(type_stmt) -> str:
    if type_stmt is None:
        return "String"

    type_name = type_stmt.arg

    if type_name == "leafref":
        if hasattr(type_stmt, "i_type_spec") and type_stmt.i_type_spec is not None:
            ts = type_stmt.i_type_spec
            if hasattr(ts, "i_target_node") and ts.i_target_node is not None:
                target_type = ts.i_target_node.search_one("type")
                if target_type is not None:
                    return _resolve_type(target_type)
        return "String"

    if type_name == "enumeration":
        return _ENUM_SENTINEL

    if type_name == "bits":
        return _BITS_SENTINEL

    if type_name == "binary":
        return "Vec<u8>"

    if type_name in _YANG_TO_RUST:
        return _YANG_TO_RUST[type_name]

    if ":" in type_name:
        unprefixed = type_name.split(":", 1)[1]
        if unprefixed in _YANG_TO_RUST:
            return _YANG_TO_RUST[unprefixed]

    if hasattr(type_stmt, "i_typedef") and type_stmt.i_typedef is not None:
        td_type = type_stmt.i_typedef.search_one("type")
        if td_type is not None:
            return _resolve_type(td_type)

    if hasattr(type_stmt, "i_type_spec") and type_stmt.i_type_spec is not None:
        ts = type_stmt.i_type_spec
        if hasattr(ts, "name") and ts.name in _YANG_TO_RUST:
            return _YANG_TO_RUST[ts.name]

    return "String"


def _find_enum_stmts(type_stmt):
    if type_stmt is None:
        return []
    enums = type_stmt.search("enum")
    if enums:
        return enums
    if hasattr(type_stmt, "i_typedef") and type_stmt.i_typedef is not None:
        td_type = type_stmt.i_typedef.search_one("type")
        if td_type is not None:
            return _find_enum_stmts(td_type)
    return []


def _find_bits_stmts(type_stmt):
    """Find ``bit`` substatements through the typedef chain."""
    if type_stmt is None:
        return []
    bits = type_stmt.search("bit")
    if bits:
        return bits
    if hasattr(type_stmt, "i_typedef") and type_stmt.i_typedef is not None:
        td_type = type_stmt.i_typedef.search_one("type")
        if td_type is not None:
            return _find_bits_stmts(td_type)
    return []


def _find_bits_typedef_name(type_stmt) -> str | None:
    """Return the PascalCase typedef name for a named bits type.

    Return None for all other types.
    """
    if type_stmt is None:
        return None
    if type_stmt.arg == "bits":
        return None
    if hasattr(type_stmt, "i_typedef") and type_stmt.i_typedef is not None:
        td_type = type_stmt.i_typedef.search_one("type")
        if td_type is not None and td_type.arg == "bits":
            return _yang_to_pascal(type_stmt.i_typedef.arg)
        if td_type is not None:
            return _find_bits_typedef_name(td_type)
    return None


def _find_enum_typedef_name(type_stmt) -> str | None:
    if type_stmt is None:
        return None
    if type_stmt.arg == "enumeration":
        return None
    if hasattr(type_stmt, "i_typedef") and type_stmt.i_typedef is not None:
        td_type = type_stmt.i_typedef.search_one("type")
        if td_type is not None and td_type.arg == "enumeration":
            return _yang_to_pascal(type_stmt.i_typedef.arg)
        if td_type is not None:
            return _find_enum_typedef_name(td_type)
    return None


def _get_desc(stmt) -> str | None:
    desc = stmt.search_one("description")
    return desc.arg if desc is not None else None


def _first_line(text: str | None) -> str | None:
    if not text:
        return None
    for raw in text.strip().split("\n"):
        line = raw.strip()
        if line:
            return line
    return None


def _doc_lines(text: str, max_lines: int | None = None) -> list[str]:
    lines = [raw.strip() for raw in text.strip().split("\n")]
    if max_lines is not None:
        return lines[:max_lines]
    return lines


def _source_module(stmt) -> str | None:
    """Return the YANG module name that defines this node."""
    if hasattr(stmt, "i_orig_module") and stmt.i_orig_module is not None:
        return stmt.i_orig_module.arg
    if hasattr(stmt, "i_module") and stmt.i_module is not None:
        return stmt.i_module.arg
    return None


# Map each YANG grouping name to a short PascalCase prefix.
# For example, map "inline-or-keystore-end-entity-cert-with-key-grouping" to
# a shorter prefix.
_GROUPING_PREFIX_MAP = {
    # These groupings are from ietf-keystore.
    "inline-or-keystore-end-entity-cert-with-key-grouping": "EndEntityCertWithKey",
    "inline-or-keystore-asymmetric-key-grouping": "AsymmetricKey",
    "inline-or-keystore-symmetric-key-grouping": "SymmetricKey",
    # These groupings are from ietf-truststore.
    "inline-or-truststore-certs-grouping": "Certs",
    "inline-or-truststore-public-keys-grouping": "PublicKeys",
    # These groupings are from ietf-crypto-types.
    "private-key-grouping": "PrivateKey",
    "symmetric-key-grouping": "SymmetricKey",
    "encrypted-value-grouping": "EncryptedValue",
    # This grouping is from ietf-tls-common.
    "hello-params-grouping": "HelloParams",
    # This grouping is from ietf-tls-client.
    "tls-client-grouping": "TlsClient",
}


def _grouping_prefix(stmt) -> str:
    """Create a PascalCase prefix from the nearest YANG grouping name.
    
    Return an empty string if there is no grouping context.
    """
    if not hasattr(stmt, "i_uses") or not stmt.i_uses:
        return ""
    # The last uses statement in the chain identifies the nearest grouping.
    last_uses = stmt.i_uses[-1]
    grp_name = last_uses.arg
    # Remove the module prefix, for example, "ks:inline-or-keystore-...".
    if ":" in grp_name:
        grp_name = grp_name.split(":", 1)[1]
    # Use the curated map first.
    if grp_name in _GROUPING_PREFIX_MAP:
        return _GROUPING_PREFIX_MAP[grp_name]
    # Otherwise, remove "-grouping" and convert the grouping name.
    clean = grp_name.removesuffix("-grouping")
    return _yang_to_pascal(clean)


def _leaf_is_optional(stmt) -> bool:
    if _is_mandatory(stmt):
        return False
    if stmt.search_one("default") is not None:
        return False
    parent = stmt.parent
    if parent is not None and parent.keyword == "list":
        key_stmt = parent.search_one("key")
        if key_stmt is not None and stmt.arg in key_stmt.arg.split():
            return False
    return True


def _resolve_default(yang_default: str, rust_type: str) -> str | None:
    """Convert a YANG default string to a Rust expression string.
    
    Return None if the value matches Rust's built-in Default::default().
    For example, bool uses false and integer types use 0.
    """
    # Convert a Boolean value.
    if rust_type == "bool":
        if yang_default == "false":
            return None  # bool::default() is false.
        return "true"

    # Convert an integer value.
    if rust_type in ("u8", "u16", "u32", "u64", "i8", "i16", "i32", "i64"):
        if yang_default == "0":
            return None  # The integer default is 0.
        return yang_default

    # Convert a floating-point value.
    if rust_type == "f64":
        return yang_default

    # Convert a string-like value.
    if rust_type == "String":
        return f'"{yang_default}".to_owned()'

    # The generated parser accepts identityref defaults and returns the same values.
    if ":" in yang_default:
        return (
            f'{rust_type}::from_rfc7951_str("{yang_default}")'
            '.expect("generated YANG identityref default must be valid")'
        )

    # Bitflag defaults contain space-separated flag names.
    if " " in yang_default:
        parts = [
            f"{rust_type}::{token.upper().replace('-', '_')}"
            for token in yang_default.split()
        ]
        return " | ".join(parts)

    # YANG enumeration defaults map directly to the generated PascalCase variant.
    if "<" not in rust_type:
        return f"{rust_type}::{_yang_to_pascal(yang_default)}"

    # No map rule produced a Rust expression that compiles. A comment
    # placeholder creates a function without a return value. Thus, stop code
    # generation. A maintainer must extend the resolver or remove the YANG default.
    raise NotImplementedError(
        f"yang2rust: Cannot resolve YANG default {yang_default!r} for "
        f"Rust type {rust_type!r}. Extend _resolve_default() to handle this case."
    )


# ---------------------------------------------------------------------------
# Intermediate representations
# ---------------------------------------------------------------------------

class Field:
    __slots__ = ("yang_name", "rust_name", "rust_type", "optional",
                 "is_vec", "doc", "default_value", "serde_name", "secret_kind")

    def __init__(self, yang_name, rust_type, *, optional=False,
                 is_vec=False, doc=None, default_value=None, serde_name=None,
                 secret_kind=None):
        self.yang_name = yang_name
        self.rust_name = _yang_to_snake(yang_name)
        self.rust_type = rust_type
        self.optional = optional
        self.is_vec = is_vec
        self.doc = doc
        # This value contains (yang_default_str, rust_expr), or it is None.
        self.default_value: tuple[str, str] | None = default_value
        self.serde_name = serde_name or yang_name
        self.secret_kind = secret_kind

    def type_string(self) -> str:
        t = self.rust_type
        if self.is_vec:
            t = f"Vec<{t}>"
        if self.optional:
            t = f"Option<{t}>"
        return t


class Struct:
    __slots__ = ("name", "fields", "doc", "choices")

    def __init__(self, name, doc=None):
        self.name = name
        self.fields: list[Field] = []
        self.choices: list[ChoiceGroup] = []
        self.doc = doc


class ChoiceGroup:
    """Store metadata for a flattened YANG choice node."""
    __slots__ = ("yang_name", "mandatory", "cases")

    def __init__(self, yang_name: str, mandatory: bool):
        self.yang_name = yang_name
        self.mandatory = mandatory
        # Each case contains (case_yang_name, [field_yang_names]).
        self.cases: list[tuple[str, list[str]]] = []


class EnumVariant:
    __slots__ = ("yang_name", "rust_name", "doc")

    def __init__(self, yang_name, doc=None):
        self.yang_name = yang_name
        self.rust_name = _yang_to_pascal(yang_name)
        self.doc = doc


class Enum:
    __slots__ = ("name", "variants", "doc")

    def __init__(self, name, doc=None):
        self.name = name
        self.variants: list[EnumVariant] = []
        self.doc = doc


class BitflagsBit:
    __slots__ = ("yang_name", "rust_name", "position", "doc")

    def __init__(self, yang_name, position, doc=None):
        self.yang_name = yang_name
        self.rust_name = yang_name.upper().replace("-", "_")
        self.position = position
        self.doc = doc


class Bitflags:
    __slots__ = ("name", "bits", "doc")

    def __init__(self, name, doc=None):
        self.name = name
        self.bits: list[BitflagsBit] = []
        self.doc = doc


class IdentityValue:
    """Store one concrete identity that derives from a base."""
    __slots__ = ("yang_name", "rust_name", "module_name", "features", "doc")

    def __init__(self, yang_name: str, module_name: str,
                 features: list[str] | None = None, doc: str | None = None):
        self.yang_name = yang_name
        self.rust_name = _yang_to_pascal(yang_name)
        self.module_name = module_name
        self.features = features or []
        self.doc = doc

    def rfc7951_name(self) -> str:
        """Return the module-qualified RFC 7951 JSON string."""
        return f"{self.module_name}:{self.yang_name}"


class IdentitySet:
    """Store concrete identities that derive from a YANG base identity."""
    __slots__ = ("name", "base_name", "base_module", "values", "doc")

    def __init__(self, name: str, base_name: str, base_module: str,
                 doc: str | None = None):
        self.name = name
        self.base_name = base_name
        self.base_module = base_module
        self.values: list[IdentityValue] = []
        self.doc = doc


class ModuleTypes:
    """Store the collected types for one YANG module."""

    def __init__(self, yang_name: str, rust_name: str):
        self.yang_name = yang_name
        self.rust_name = rust_name
        self.structs: OrderedDict[str, Struct] = OrderedDict()
        self.enums: OrderedDict[str, Enum] = OrderedDict()
        self.bitflags: OrderedDict[str, Bitflags] = OrderedDict()
        self.identity_sets: OrderedDict[str, IdentitySet] = OrderedDict()
        self.typedefs: OrderedDict[str, str] = OrderedDict()
        self._used: set[str] = set()

    def unique_name(self, desired: str) -> str:
        name = desired
        n = 2
        while name in self._used:
            name = f"{desired}{n}"
            n += 1
        self._used.add(name)
        return name


# ---------------------------------------------------------------------------
# Identity resolution helpers
# ---------------------------------------------------------------------------

def _find_derived_identities(base_identity, ctx) -> list[dict]:
    """Find identities in loaded modules that derive from *base_identity*.

    Return dictionaries with the keys name, module, features, and doc.
    *base_identity* is a pyang identity statement object from i_identity.
    """
    from pyang.types import is_derived_from

    derived = []
    for modname, mod_stmt in _iter_all_modules(ctx):
        for ident_name, ident_stmt in getattr(mod_stmt, "i_identities", {}).items():
            if is_derived_from(ident_stmt, base_identity):
                features = [f.arg for f in ident_stmt.search("if-feature")]
                derived.append({
                    "name": ident_name,
                    "module": modname,
                    "features": features,
                    "doc": _get_desc(ident_stmt),
                })
    return derived


def _iter_all_modules(ctx):
    """Yield (module_name, module_stmt) for each module or submodule in ctx."""
    seen = set()
    for key, mod_list in ctx.modules.items():
        # In pyang 2.x, ctx.modules maps (name, revision) to module_stmt.
        # The value can also be a list. Handle both forms.
        if isinstance(mod_list, list):
            for m in mod_list:
                if m.arg not in seen:
                    seen.add(m.arg)
                    yield m.arg, m
        else:
            m = mod_list
            if m.arg not in seen:
                seen.add(m.arg)
                yield m.arg, m


def _resolve_identityref_base(type_stmt):
    """Return the resolved base identity statement for an identityref type.

    Return None if the base cannot be resolved.
    """
    base = type_stmt.search_one("base")
    if base is None:
        return None
    return getattr(base, "i_identity", None)


# ---------------------------------------------------------------------------
# The collector walks the resolved YANG data tree and groups nodes by source module.
# ---------------------------------------------------------------------------

class Collector:
    def __init__(self, ctx=None, secret_fields: SecretFieldManifest | None = None):
        self.modules: OrderedDict[str, ModuleTypes] = OrderedDict()
        # Map a fingerprint to (module_name, struct_name) to remove duplicates.
        self._fingerprints: dict[str, tuple[str, str]] = {}
        self._ctx = ctx
        self._secret_fields = secret_fields

    def _get_mod(self, yang_mod_name: str) -> ModuleTypes:
        if yang_mod_name not in self.modules:
            rust_name = _MODULE_MAP.get(yang_mod_name, _yang_to_snake(yang_mod_name))
            self.modules[yang_mod_name] = ModuleTypes(yang_mod_name, rust_name)
        return self.modules[yang_mod_name]

    def _mod_for_stmt(self, stmt) -> ModuleTypes:
        src = _source_module(stmt)
        if src and src not in _SKIP_MODULES:
            return self._get_mod(src)
        return self._get_mod(self._current_top_module)

    def collect_module(self, module):
        self._current_top_module = module.arg

        # Collect typedefs.
        for td in module.search("typedef"):
            td_type = td.search_one("type")
            rust_type = _resolve_type(td_type)
            td_pascal = _yang_to_pascal(td.arg)
            mod = self._get_mod(module.arg)
            if rust_type == _ENUM_SENTINEL:
                self._collect_enum_typedef(td, mod)
            elif rust_type == _BITS_SENTINEL:
                self._collect_bits_typedef(td, mod)
            else:
                mod.typedefs[td_pascal] = rust_type

        # Collect top-level data nodes.
        for child in _get_children(module):
            self._process_node(child, parent_prefix="")

        # Collect augmentations.
        for augment in module.search("augment"):
            for child in _get_children(augment):
                self._process_node(child, parent_prefix="")

    def verify_secret_fields(self) -> None:
        if self._secret_fields is not None:
            self._secret_fields.verify_complete()

    def _collect_enum_typedef(self, td, mod: ModuleTypes):
        td_type = td.search_one("type")
        enum_name = _yang_to_pascal(td.arg)
        rust_enum = Enum(enum_name, _get_desc(td))
        for e in td_type.search("enum"):
            rust_enum.variants.append(EnumVariant(e.arg, _get_desc(e)))
        if rust_enum.variants:
            mod.enums[enum_name] = rust_enum

    def _collect_bits_typedef(self, td, mod: ModuleTypes):
        td_type = td.search_one("type")
        bf_name = _yang_to_pascal(td.arg)
        bf = Bitflags(bf_name, _get_desc(td))
        for i, bit_stmt in enumerate(td_type.search("bit")):
            pos_stmt = bit_stmt.search_one("position")
            pos = int(pos_stmt.arg) if pos_stmt else i
            bf.bits.append(BitflagsBit(bit_stmt.arg, pos, _get_desc(bit_stmt)))
        if bf.bits:
            mod.bitflags[bf_name] = bf

    # Name types within a module.

    def _struct_name(self, stmt, parent_prefix: str) -> tuple[ModuleTypes, str, bool]:
        """Return (module, name, already_existed) for a container or list.

        A structural fingerprint removes duplicate structures. If two nodes
        have the same module and child structure, reuse the existing name.

        When available, the YANG grouping name supplies the structure name.
        This produces ``keystore::AsymmetricKeyInlineDefinition`` instead of
        ``keystore::ClientCredentialsCertificateInlineDefinition``.
        """
        mod = self._mod_for_stmt(stmt)
        fp = self._fingerprint(stmt)

        # Reuse this exact structure if it exists in the same module.
        fp_key = f"{mod.yang_name}:{fp}"
        if fp_key in self._fingerprints:
            existing_mod_name, existing_name = self._fingerprints[fp_key]
            return mod, existing_name, True

        pascal = _yang_to_pascal(stmt.arg)

        # Get a context prefix from the nearest YANG grouping name.
        # Do not use the parent at the usage site. This gives names such as
        # ``AsymmetricKeyInlineDefinition`` instead of
        # ``ClientCredentialsCertificateInlineDefinition``.
        grp_prefix = _grouping_prefix(stmt)

        if grp_prefix and (pascal in mod._used or pascal in _GENERIC):
            pascal = f"{grp_prefix}{pascal}"
        elif parent_prefix and (pascal in mod._used or pascal in _GENERIC):
            pascal = f"{parent_prefix}{pascal}"

        name = mod.unique_name(pascal)
        self._fingerprints[fp_key] = (mod.yang_name, name)
        return mod, name, False

    @staticmethod
    def _fingerprint(stmt) -> str:
        """Create a structural fingerprint of a container or list node.
        
        Two nodes with the same fingerprint have the same child structure.
        Their leaf names, types, and nested container shapes are equal.
        """
        parts = []
        children = _get_children(stmt)
        for ch in children:
            if ch.keyword == "leaf":
                t = ch.search_one("type")
                type_name = t.arg if t else "?"
                parts.append(f"L:{ch.arg}:{type_name}")
            elif ch.keyword == "leaf-list":
                t = ch.search_one("type")
                type_name = t.arg if t else "?"
                parts.append(f"LL:{ch.arg}:{type_name}")
            elif ch.keyword in ("container", "list"):
                # Recurse to get the shape.
                sub_fp = Collector._fingerprint(ch)
                parts.append(f"C:{ch.arg}:{sub_fp}")
            elif ch.keyword == "choice":
                sub_fp = Collector._fingerprint(ch)
                parts.append(f"CH:{ch.arg}:{sub_fp}")
            elif ch.keyword == "case":
                sub_fp = Collector._fingerprint(ch)
                parts.append(f"CA:{ch.arg}:{sub_fp}")
        return "|".join(parts)

    # Send each node to the applicable function.

    def _process_node(self, stmt, parent_prefix: str, current_mod: ModuleTypes | None = None) -> Field | None:
        kw = stmt.keyword
        if kw == "container":
            return self._process_container(stmt, parent_prefix)
        if kw == "list":
            return self._process_list(stmt, parent_prefix)
        if kw == "leaf":
            return self._process_leaf(stmt, parent_prefix, current_mod)
        if kw == "leaf-list":
            return self._process_leaf_list(stmt, parent_prefix, current_mod)
        if kw == "choice":
            return None  # The caller uses _flatten_choice.
        return None

    def _process_container(self, stmt, parent_prefix: str) -> Field:
        mod, sname, existed = self._struct_name(stmt, parent_prefix)
        if not existed:
            rs = Struct(sname, _get_desc(stmt))
            self._fill_children(stmt, rs, sname, mod)
            mod.structs[sname] = rs

        type_ref = self._qualified_type(stmt, sname)
        return Field(stmt.arg, type_ref, optional=True, doc=_get_desc(stmt))

    def _process_list(self, stmt, parent_prefix: str) -> Field:
        mod, sname, existed = self._struct_name(stmt, parent_prefix)
        if not existed:
            rs = Struct(sname, _get_desc(stmt))
            self._fill_children(stmt, rs, sname, mod)
            mod.structs[sname] = rs

        type_ref = self._qualified_type(stmt, sname)
        return Field(stmt.arg, type_ref, is_vec=True, doc=_get_desc(stmt))

    def _process_leaf(self, stmt, parent_prefix: str, current_mod: ModuleTypes | None = None) -> Field:
        type_stmt = stmt.search_one("type")
        rust_type = _resolve_type(type_stmt)
        field_mod = current_mod or self._mod_for_stmt(stmt)

        if rust_type == _ENUM_SENTINEL:
            mod = self._mod_for_stmt(stmt)
            td_name = _find_enum_typedef_name(type_stmt)
            if td_name and td_name in mod.enums:
                rust_type = td_name
            else:
                enum_name = td_name or _yang_to_pascal(stmt.arg)
                enum_name = mod.unique_name(enum_name)
                rust_enum = Enum(enum_name, _get_desc(stmt))
                for e in _find_enum_stmts(type_stmt):
                    rust_enum.variants.append(EnumVariant(e.arg, _get_desc(e)))
                mod.enums[enum_name] = rust_enum
                rust_type = enum_name
            if mod.rust_name != field_mod.rust_name:
                rust_type = f"{mod.rust_name}::{rust_type}"

        if rust_type == _BITS_SENTINEL:
            mod = self._mod_for_stmt(stmt)
            td_name = _find_bits_typedef_name(type_stmt)
            bf_name = td_name or _yang_to_pascal(stmt.arg)
            if bf_name not in mod.bitflags:
                bf_name = mod.unique_name(bf_name)
                bf = Bitflags(bf_name, _get_desc(stmt))
                for i, bit_stmt in enumerate(_find_bits_stmts(type_stmt)):
                    pos_stmt = bit_stmt.search_one("position")
                    pos = int(pos_stmt.arg) if pos_stmt else i
                    bf.bits.append(BitflagsBit(bit_stmt.arg, pos, _get_desc(bit_stmt)))
                mod.bitflags[bf_name] = bf
            rust_type = bf_name
            if mod.rust_name != field_mod.rust_name:
                rust_type = f"{mod.rust_name}::{rust_type}"

        if rust_type == _IDENTITYREF_SENTINEL:
            # Resolve the base identity and collect its derived identities.
            base_ident = _resolve_identityref_base(type_stmt)
            if base_ident is not None and self._ctx is not None:
                base_mod = _source_module(base_ident) or "unknown"
                # Use the base identity name for the identity set.
                set_name = _yang_to_pascal(base_ident.arg)
                # Put identity sets in the module that defines the base.
                target_mod = self._get_mod(base_mod) if base_mod not in _SKIP_MODULES else self._mod_for_stmt(stmt)
                if set_name not in target_mod.identity_sets:
                    derived = _find_derived_identities(base_ident, self._ctx)
                    if derived:
                        iset = IdentitySet(
                            set_name, base_ident.arg, base_mod,
                            _get_desc(base_ident),
                        )
                        for d in derived:
                            iset.values.append(IdentityValue(
                                d["name"], d["module"],
                                d["features"], d["doc"],
                            ))
                        target_mod.identity_sets[set_name] = iset
                rust_type = set_name
                if target_mod.rust_name != field_mod.rust_name:
                    rust_type = f"{target_mod.rust_name}::{set_name}"
            else:
                rust_type = "String"

        optional = _leaf_is_optional(stmt)
        source_module = _source_module(stmt) or field_mod.yang_name
        secret_kind = None
        if self._secret_fields is not None:
            secret_kind = self._secret_fields.match(source_module, stmt.arg, rust_type)
            if secret_kind == "string":
                rust_type = "tacacsrs_secrets::SecretString"
            elif secret_kind == "binary":
                rust_type = "tacacsrs_secrets::SecretBytes"

        # Get the YANG default value.
        default_value = None
        default_stmt = stmt.search_one("default")
        has_yang_default = default_stmt is not None
        if has_yang_default:
            rust_expr = _resolve_default(default_stmt.arg, rust_type)
            if rust_expr is not None:
                default_value = (default_stmt.arg, rust_expr)
            # An empty tuple shows that the YANG default matches
            # Rust Default::default(). _leaf_is_optional already made this
            # field not optional, but it still needs #[serde(default)].
            else:
                default_value = (default_stmt.arg, "")

        return Field(
            stmt.arg,
            rust_type,
            optional=optional,
            doc=_get_desc(stmt),
            default_value=default_value,
            serde_name=self._serde_name(stmt, field_mod),
            secret_kind=secret_kind,
        )

    def _process_leaf_list(self, stmt, parent_prefix: str, current_mod: ModuleTypes | None = None) -> Field:
        type_stmt = stmt.search_one("type")
        rust_type = _resolve_type(type_stmt)
        field_mod = current_mod or self._mod_for_stmt(stmt)
        if rust_type == _ENUM_SENTINEL:
            mod = self._mod_for_stmt(stmt)
            td_name = _find_enum_typedef_name(type_stmt)
            if td_name and td_name in mod.enums:
                rust_type = td_name
            else:
                enum_name = td_name or _yang_to_pascal(stmt.arg)
                enum_name = mod.unique_name(enum_name)
                rust_enum = Enum(enum_name, _get_desc(stmt))
                for e in _find_enum_stmts(type_stmt):
                    rust_enum.variants.append(EnumVariant(e.arg, _get_desc(e)))
                mod.enums[enum_name] = rust_enum
                rust_type = enum_name
            if mod.rust_name != field_mod.rust_name:
                rust_type = f"{mod.rust_name}::{rust_type}"
        if rust_type == _BITS_SENTINEL:
            mod = self._mod_for_stmt(stmt)
            td_name = _find_bits_typedef_name(type_stmt)
            bf_name = td_name or _yang_to_pascal(stmt.arg)
            if bf_name not in mod.bitflags:
                bf_name = mod.unique_name(bf_name)
                bf = Bitflags(bf_name, _get_desc(stmt))
                for i, bit_stmt in enumerate(_find_bits_stmts(type_stmt)):
                    pos_stmt = bit_stmt.search_one("position")
                    pos = int(pos_stmt.arg) if pos_stmt else i
                    bf.bits.append(BitflagsBit(bit_stmt.arg, pos, _get_desc(bit_stmt)))
                mod.bitflags[bf_name] = bf
            rust_type = bf_name
            if mod.rust_name != field_mod.rust_name:
                rust_type = f"{mod.rust_name}::{rust_type}"
        if rust_type == _IDENTITYREF_SENTINEL:
            base_ident = _resolve_identityref_base(type_stmt)
            if base_ident is not None and self._ctx is not None:
                base_mod = _source_module(base_ident) or "unknown"
                set_name = _yang_to_pascal(base_ident.arg)
                target_mod = self._get_mod(base_mod) if base_mod not in _SKIP_MODULES else field_mod
                if set_name not in target_mod.identity_sets:
                    derived = _find_derived_identities(base_ident, self._ctx)
                    if derived:
                        iset = IdentitySet(
                            set_name, base_ident.arg, base_mod,
                            _get_desc(base_ident),
                        )
                        for d in derived:
                            iset.values.append(IdentityValue(
                                d["name"], d["module"],
                                d["features"], d["doc"],
                            ))
                        target_mod.identity_sets[set_name] = iset
                rust_type = set_name
                if target_mod.rust_name != field_mod.rust_name:
                    rust_type = f"{target_mod.rust_name}::{set_name}"
            else:
                rust_type = "String"
        return Field(
            stmt.arg,
            rust_type,
            is_vec=True,
            doc=_get_desc(stmt),
            serde_name=self._serde_name(stmt, field_mod),
        )

    @staticmethod
    def _serde_name(stmt, field_mod: ModuleTypes) -> str:
        src = _source_module(stmt)
        # Project-owned augment leaves come from separate modules. Thus, they
        # use module-qualified RFC 7951 JSON member names. The qualifier is the
        # source YANG module name, not the module prefix.
        if (
            src
            and (src in _PROJECT_MODULE_NAMES or src.startswith(_PROJECT_MODULE_PREFIX))
            and src != field_mod.yang_name
        ):
            return f"{src}:{stmt.arg}"
        return stmt.arg

    def _flatten_choice(self, choice_stmt, parent_prefix: str, current_mod: ModuleTypes) -> tuple[list[Field], ChoiceGroup]:
        """Flatten case branches into ``Option<T>`` fields and record choice metadata."""
        mandatory = _is_mandatory(choice_stmt)
        choice_group = ChoiceGroup(choice_stmt.arg, mandatory)
        fields = []

        cases = [ch for ch in _get_children(choice_stmt) if ch.keyword == "case"]
        if not cases:
            cases = [choice_stmt]

        for case in cases:
            case_field_names = []
            for child in _get_children(case):
                if child.keyword == "choice":
                    # Recurse into the nested choice and merge it.
                    nested_fields, nested_group = self._flatten_choice(child, parent_prefix, current_mod)
                    fields.extend(nested_fields)
                    # Attach the nested choice as a separate group.
                    choice_group.cases.append((
                        f"{case.arg}/{child.arg}",
                        [f.yang_name for f in nested_fields],
                    ))
                else:
                    field = self._process_node(child, parent_prefix, current_mod)
                    if field is not None:
                        field.optional = True
                        fields.append(field)
                        case_field_names.append(field.yang_name)
            if case_field_names:
                choice_group.cases.append((case.arg, case_field_names))

        return fields, choice_group

    def _fill_children(self, stmt, rs: Struct, sname: str, current_mod: ModuleTypes):
        for child in _get_children(stmt):
            if child.keyword == "choice":
                choice_fields, choice_group = self._flatten_choice(child, sname, current_mod)
                rs.fields.extend(choice_fields)
                if choice_group.cases:
                    rs.choices.append(choice_group)
            else:
                field = self._process_node(child, sname, current_mod)
                if field is not None:
                    rs.fields.append(field)

    def _qualified_type(self, stmt, local_name: str) -> str:
        """Return a type reference with module:: for a cross-module type."""
        src = _source_module(stmt)
        if not src or src in _SKIP_MODULES:
            src = self._current_top_module
        src_rust = _MODULE_MAP.get(src, _yang_to_snake(src))
        top_rust = _MODULE_MAP.get(self._current_top_module,
                                   _yang_to_snake(self._current_top_module))
        # Qualify a type if it is in a different Rust module from its structure.
        # The emitter wraps each module. Thus, a reference in the same module
        # uses only the type name.
        return f"{src_rust}::{local_name}"


_GENERIC = frozenset({
    "InlineDefinition", "CentralKeystoreReference",
    "CentralTruststoreReference", "Certificate", "Server",
    "EncryptedBy", "EncryptedPrivateKey", "EncryptedSymmetricKey",
    "TlsVersions", "CipherSuites", "HelloParams",
    "ClientIdentity", "ServerAuthentication",
    "CaCerts", "EeCerts", "RawPublicKeys", "PublicKey",
})


# ---------------------------------------------------------------------------
# The emitter writes Rust modules.
# ---------------------------------------------------------------------------

class RustEmitter:
    def __init__(self, fd: TextIO, collector: Collector):
        self.fd = fd
        self.c = collector

    def emit(self):
        w = self.fd.write
        w("// @generated\n")
        w("// Auto-generated from YANG modules by yang2rust.py — DO NOT EDIT\n\n")
        w("#![allow(dead_code)]\n")
        w("#![allow(non_camel_case_types)]\n")
        w("#![allow(clippy::doc_markdown)]\n\n")
        w("#![allow(clippy::too_long_first_doc_paragraph)]\n\n")
        w("#![allow(rustdoc::broken_intra_doc_links)]\n\n")
        w("use serde::{Deserialize, Serialize};\n\n")

        # Write each module.
        top_module = None
        for mod in self.c.modules.values():
            if not mod.structs and not mod.enums and not mod.typedefs and not mod.bitflags and not mod.identity_sets:
                continue
            self._emit_module(mod)
            # The first module with a TacacsPlus-like root structure is the top module.
            if top_module is None and any(
                s.name in ("TacacsPlus", "TacacsPlusConfig")
                for s in mod.structs.values()
            ):
                top_module = mod

        # Write the root wrapper for RFC 7951 JSON encoding.
        if top_module is not None:
            yang_name = top_module.yang_name
            rust_mod = top_module.rust_name
            # Find the root container name.
            for s in top_module.structs.values():
                if s.name in ("TacacsPlus", "TacacsPlusConfig"):
                    self._emit_root_wrapper(yang_name, rust_mod, s.name)
                    break

    def _emit_root_wrapper(self, yang_module: str, rust_mod: str, struct_name: str):
        w = self.fd.write
        # The YANG augmentation key has the form module-name:container-name.
        # For ietf-system-tacacs-plus, the container name is "tacacs-plus".
        json_key = f"{yang_module}:tacacs-plus"

        w(f"/// Root wrapper for RFC 7951 JSON encoding.\n")
        w(f"///\n")
        w(f"/// The JSON document root key is `{json_key}`.\n")
        w(f"#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]\n")
        w(f"pub struct YangConfigRoot {{\n")
        w(f'    #[serde(rename = "{json_key}")]\n')
        w(f"    pub tacacs_plus: {rust_mod}::{struct_name},\n")
        w(f"}}\n")

    def _emit_module(self, mod: ModuleTypes):
        w = self.fd.write

        w(f"/// Types from `{mod.yang_name}`.\n")
        w(f"pub mod {mod.rust_name} {{\n")
        # Import serde derive traits only if a type derives them.
        # Enumeration, identity, and bitflag functions use qualified serde paths.
        emitted_use = False
        if mod.structs:
            w("    use serde::{Deserialize, Serialize};\n")
            emitted_use = True

        # Find the other modules to import.
        imports = set()
        for st in mod.structs.values():
            for f in st.fields:
                if "::" in f.rust_type:
                    foreign_mod = f.rust_type.split("::")[0]
                    if foreign_mod != mod.rust_name and foreign_mod != "tacacsrs_secrets":
                        imports.add(foreign_mod)
        for imp in sorted(imports):
            w(f"    use super::{imp};\n")
            emitted_use = True
        if emitted_use:
            w("\n")

        # Write typedefs.
        for name, rt in mod.typedefs.items():
            w(f"    pub type {name} = {rt};\n")
        if mod.typedefs:
            w("\n")

        # Write enumerations.
        for enum in mod.enums.values():
            self._emit_enum(enum)

        # Write bitflags.
        for bf in mod.bitflags.values():
            self._emit_bitflags(bf)

        # Write identity sets.
        for iset in mod.identity_sets.values():
            self._emit_identity_set(iset)

        # Write structures.
        for st in mod.structs.values():
            self._emit_struct(st, mod.rust_name)

        self.fd.write("}\n\n")

    def _emit_enum(self, enum: Enum):
        w = self.fd.write
        self._doc(enum.doc, "    ")
        w("    #[derive(Debug, Clone, Copy, PartialEq, Eq)]\n")
        w(f"    pub enum {enum.name} {{\n")
        for v in enum.variants:
            self._doc(v.doc, "        ")
            w(f"        {v.rust_name},\n")
        w("    }\n\n")

        w(f"    impl {enum.name} {{\n")
        w("        /// All valid values for this YANG enumeration.\n")
        w("        pub const ALL: &[Self] = &[\n")
        for v in enum.variants:
            w(f"            Self::{v.rust_name},\n")
        w("        ];\n\n")

        w("        /// RFC 7951 JSON string values accepted for this YANG enumeration.\n")
        w("        pub const ALLOWED_VALUES: &[&str] = &[\n")
        for v in enum.variants:
            w(f'            "{v.yang_name}",\n')
        w("        ];\n\n")

        w("        /// Returns the RFC 7951 JSON string.\n")
        w("        #[must_use]\n")
        w("        pub fn as_rfc7951_str(&self) -> &'static str {\n")
        w("            match self {\n")
        for v in enum.variants:
            w(f'                Self::{v.rust_name} => "{v.yang_name}",\n')
        w("            }\n")
        w("        }\n\n")

        w("        /// Parses an RFC 7951 string into this YANG enumeration.\n")
        w("        #[must_use]\n")
        w(f"        pub fn from_rfc7951_str(s: &str) -> Option<Self> {{\n")
        w("            match s {\n")
        for v in enum.variants:
            w(f'                "{v.yang_name}" => Some(Self::{v.rust_name}),\n')
        w("                _ => None,\n")
        w("            }\n")
        w("        }\n\n")

        w("        /// Checks whether the given string is a valid RFC 7951 value.\n")
        w("        #[must_use]\n")
        w("        pub fn is_valid(s: &str) -> bool {\n")
        w("            Self::from_rfc7951_str(s).is_some()\n")
        w("        }\n")
        w("    }\n\n")

        w(f"    impl<'de> serde::Deserialize<'de> for {enum.name} {{\n")
        w("        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>\n")
        w("        where\n")
        w("            D: serde::Deserializer<'de>,\n")
        w("        {\n")
        w("            let s = <String as serde::Deserialize>::deserialize(deserializer)?;\n")
        w("            Self::from_rfc7951_str(&s)\n")
        w("                .ok_or_else(|| serde::de::Error::unknown_variant(&s, Self::ALLOWED_VALUES))\n")
        w("        }\n")
        w("    }\n\n")

        w(f"    impl serde::Serialize for {enum.name} {{\n")
        w("        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>\n")
        w("        where\n")
        w("            S: serde::Serializer,\n")
        w("        {\n")
        w("            serializer.serialize_str(self.as_rfc7951_str())\n")
        w("        }\n")
        w("    }\n\n")

    def _emit_bitflags(self, bf: Bitflags):
        w = self.fd.write
        w(f"    bitflags::bitflags! {{\n")
        self._doc(bf.doc, "        ")
        w(f"        #[derive(Debug, Clone, Copy, PartialEq, Eq)]\n")
        w(f"        pub struct {bf.name}: u32 {{\n")
        for bit in bf.bits:
            self._doc(bit.doc, "            ")
            w(f"            const {bit.rust_name} = 1 << {bit.position};\n")
        w("        }\n")
        w("    }\n\n")
        # Write a custom Deserialize implementation for an RFC 7951 bit string.
        w(f"    impl<'de> serde::Deserialize<'de> for {bf.name} {{\n")
        w(f"        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>\n")
        w(f"        where\n")
        w(f"            D: serde::Deserializer<'de>,\n")
        w(f"        {{\n")
        w(f"            let s = <String as serde::Deserialize>::deserialize(deserializer)?;\n")
        w(f"            let mut bits = Self::empty();\n")
        w(f"            for token in s.split_whitespace() {{\n")
        w(f"                match token {{\n")
        for bit in bf.bits:
            w(f'                    "{bit.yang_name}" => bits |= Self::{bit.rust_name},\n')
        w(f"                    other => return Err(serde::de::Error::unknown_variant(\n")
        w(f"                        other,\n")
        names_str = ", ".join(f'"{b.yang_name}"' for b in bf.bits)
        w(f"                        &[{names_str}],\n")
        w(f"                    )),\n")
        w(f"                }}\n")
        w(f"            }}\n")
        w(f"            if bits.is_empty() {{\n")
        w(f'                return Err(serde::de::Error::custom("at least one bit must be set"));\n')
        w(f"            }}\n")
        w(f"            Ok(bits)\n")
        w(f"        }}\n")
        w(f"    }}\n\n")
        w(f"    impl serde::Serialize for {bf.name} {{\n")
        w(f"        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>\n")
        w(f"        where\n")
        w(f"            S: serde::Serializer,\n")
        w(f"        {{\n")
        w(f"            let tokens = [\n")
        for bit in bf.bits:
            w(
                f'                (Self::{bit.rust_name}, "{bit.yang_name}"),\n'
            )
        w(f"            ]\n")
        w(f"            .into_iter()\n")
        w(f"            .filter_map(|(flag, name)| self.contains(flag).then_some(name))\n")
        w(f"            .collect::<Vec<_>>()\n")
        w(f'            .join(" ");\n')
        w(f"            serializer.serialize_str(&tokens)\n")
        w(f"        }}\n")
        w(f"    }}\n\n")

    def _emit_identity_set(self, iset: IdentitySet):
        """Write an identity set as a Rust enumeration with serde functions."""
        w = self.fd.write

        w(f"    /// Valid identities derived from `{iset.base_module}:{iset.base_name}`.\n")
        self._doc(iset.doc, "    ")
        w("    #[derive(Debug, Clone, Copy, PartialEq, Eq)]\n")
        w(f"    #[allow(clippy::doc_markdown)]\n")
        w(f"    pub enum {iset.name} {{\n")
        for val in iset.values:
            self._doc(val.doc, "        ")
            if val.features:
                w(f"        /// Requires YANG features: {', '.join(val.features)}\n")
            w(f"        {val.rust_name},\n")
        w("    }\n\n")

        # Write the implementation with as_str, from_rfc7951, ALL, and ALLOWED_VALUES.
        w(f"    impl {iset.name} {{\n")

        # Write the ALL constant.
        w(f"        /// All valid identities for this base.\n")
        w(f"        pub const ALL: &[Self] = &[\n")
        for val in iset.values:
            w(f"            Self::{val.rust_name},\n")
        w("        ];\n\n")

        # Write the ALLOWED_VALUES constant for RFC 7951 JSON strings.
        w(f"        /// RFC 7951 JSON string values accepted for this identity.\n")
        w(f"        pub const ALLOWED_VALUES: &[&str] = &[\n")
        for val in iset.values:
            w(f'            "{val.rfc7951_name()}",\n')
        w("        ];\n\n")

        # Write as_rfc7951_str.
        w(f"        /// Returns the RFC 7951 module-qualified JSON string.\n")
        w(f"        #[must_use]\n")
        w(f"        pub fn as_rfc7951_str(&self) -> &'static str {{\n")
        w(f"            match self {{\n")
        for val in iset.values:
            w(f'                Self::{val.rust_name} => "{val.rfc7951_name()}",\n')
        w("            }\n")
        w("        }\n\n")

        # Write from_rfc7951_str.
        w(f"        /// Parses an RFC 7951 module-qualified string into this identity.\n")
        w(f"        #[must_use]\n")
        w(f"        pub fn from_rfc7951_str(s: &str) -> Option<Self> {{\n")
        w(f"            match s {{\n")
        for val in iset.values:
            w(f'                "{val.rfc7951_name()}" => Some(Self::{val.rust_name}),\n')
        w("                _ => None,\n")
        w("            }\n")
        w("        }\n\n")

        # Write is_valid.
        w(f"        /// Checks whether the given string is a valid RFC 7951 value for this identity.\n")
        w(f"        #[must_use]\n")
        w(f"        pub fn is_valid(s: &str) -> bool {{\n")
        w(f"            Self::from_rfc7951_str(s).is_some()\n")
        w(f"        }}\n")

        w("    }\n\n")

        w(f"    impl<'de> serde::Deserialize<'de> for {iset.name} {{\n")
        w(f"        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>\n")
        w(f"        where\n")
        w(f"            D: serde::Deserializer<'de>,\n")
        w(f"        {{\n")
        w(f"            let s = <String as serde::Deserialize>::deserialize(deserializer)?;\n")
        w(f"            Self::from_rfc7951_str(&s).ok_or_else(|| {{\n")
        w(f"                serde::de::Error::unknown_variant(&s, Self::ALLOWED_VALUES)\n")
        w(f"            }})\n")
        w(f"        }}\n")
        w(f"    }}\n\n")

        w(f"    impl serde::Serialize for {iset.name} {{\n")
        w(f"        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>\n")
        w(f"        where\n")
        w(f"            S: serde::Serializer,\n")
        w(f"        {{\n")
        w(f"            serializer.serialize_str(self.as_rfc7951_str())\n")
        w(f"        }}\n")
        w(f"    }}\n\n")

    def _emit_struct(self, st: Struct, current_mod: str):
        w = self.fd.write

        # Collect the default functions that the structure fields need.
        default_fns: dict[str, tuple[str, str, str]] = {}  # Map a field name to (fn_name, rust_type, rust_expr).
        bare_defaults: set[str] = set()  # These fields need only #[serde(default)].
        for f in st.fields:
            if f.default_value is not None:
                _yang_default, rust_expr = f.default_value
                if rust_expr:  # A nonempty value requires a function.
                    # Build a snake_case function name from the structure and field names.
                    struct_snake = st.name[0].lower() + st.name[1:]
                    # Convert PascalCase to snake_case.
                    import re
                    struct_snake = re.sub(r'([A-Z])', r'_\1', struct_snake).lower().lstrip('_')
                    fn_name = f"default_{struct_snake}_{f.rust_name}"
                    default_fns[f.yang_name] = (fn_name, f.rust_type, rust_expr)
                else:  # An empty value matches Rust Default::default().
                    bare_defaults.add(f.yang_name)

        # Write the default functions before the structure.
        for fn_name, rust_type, rust_expr in default_fns.values():
            # Remove the module prefix from local types.
            rt = rust_type.replace(f"{current_mod}::", "")
            w(f"    fn {fn_name}() -> {rt} {{ {rust_expr} }}\n")
        if default_fns:
            w("\n")

        self._doc(st.doc, "    ")
        w("    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]\n")
        w('    #[serde(rename_all = "kebab-case")]\n')
        w(f"    pub struct {st.name} {{\n")
        for f in st.fields:
            self._emit_field(f, current_mod, default_fns, bare_defaults)
        w("    }\n\n")

        # Write choice-group constants for flattened choices.
        if st.choices:
            self._emit_choice_constants(st)

    def _emit_field(self, f: Field, current_mod: str, default_fns: dict, bare_defaults: set):
        w = self.fd.write
        self._doc(f.doc, "        ")

        if f.serde_name != f.rust_name or _needs_rename(f.serde_name):
            w(f'        #[serde(rename = "{f.serde_name}")]\n')

        if f.rust_type == "Vec<u8>" and f.secret_kind is None:
            if f.is_vec:
                w('        #[serde(with = "crate::serde_helpers::base64_binary::vec_bytes")]\n')
            elif f.optional:
                w('        #[serde(with = "crate::serde_helpers::base64_binary::option_bytes")]\n')
            else:
                w('        #[serde(with = "crate::serde_helpers::base64_binary::bytes")]\n')

        if f.optional or f.is_vec:
            w("        #[serde(default)]\n")
            if f.optional:
                w('        #[serde(skip_serializing_if = "Option::is_none")]\n')
            elif f.is_vec:
                w('        #[serde(skip_serializing_if = "Vec::is_empty")]\n')
        elif f.yang_name in default_fns:
            fn_name = default_fns[f.yang_name][0]
            w(f'        #[serde(default = "{fn_name}")]\n')
        elif f.yang_name in bare_defaults:
            w("        #[serde(default)]\n")

        # Resolve the type reference and remove its local module prefix.
        type_str = f.type_string()
        own_prefix = f"{current_mod}::"
        type_str = type_str.replace(own_prefix, "")

        name = _safe_name(f.rust_name)
        w(f"        pub {name}: {type_str},\n")

    def _doc(self, text, indent, max_lines=None):
        if not text:
            return
        for line in _doc_lines(text, max_lines):
            self.fd.write(f"{indent}/// {line}\n")

    def _emit_choice_constants(self, st: Struct):
        w = self.fd.write
        w(f"    /// Choice constraints for [`{st.name}`].\n")
        w(f"    impl {st.name} {{\n")
        for cg in st.choices:
            const_name = f"CHOICE_{_yang_to_snake(cg.yang_name).upper()}"
            mandatory_str = "true" if cg.mandatory else "false"
            w(f"        /// YANG choice `{cg.yang_name}` ")
            w(f"({'mandatory' if cg.mandatory else 'optional'}).\n")
            w(f"        ///\n")
            w(f"        /// Each inner slice is one case; at most one case may have fields set.\n")
            w(f"        pub const {const_name}: &[(&str, &[&str])] = &[\n")
            for case_name, field_names in cg.cases:
                fields_str = ", ".join(f'"{f}"' for f in field_names)
                w(f'            ("{case_name}", &[{fields_str}]),\n')
            w("        ];\n")
            w(f"        pub const {const_name}_MANDATORY: bool = {mandatory_str};\n")
        w("    }\n\n")


# ---------------------------------------------------------------------------
# The plug-in class.
# ---------------------------------------------------------------------------

class YangToRustPlugin(plugin.PyangPlugin):
    def __init__(self):
        super().__init__()
        self.multiple_modules = True

    def add_output_format(self, fmts):
        self.multiple_modules = True
        fmts["rust"] = self

    def setup_fmt(self, ctx):
        ctx.implicit_errors = False

    def emit(self, ctx, modules, fd):
        secret_fields = SecretFieldManifest.load(SECRET_FIELDS_PATH)
        collector = Collector(ctx, secret_fields)
        for module in modules:
            collector.collect_module(module)
        collector.verify_secret_fields()
        RustEmitter(fd, collector).emit()
