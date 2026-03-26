"""pyang plugin that generates Rust struct/enum definitions from YANG modules.

The output is a single Rust file with serde Deserialize derives suitable for
parsing RFC 7951 JSON-encoded YANG data.

Usage:
    pyang --plugindir <dir-containing-this-file> -f rust \\
          -p <search-paths> module.yang
"""

from __future__ import annotations

from collections import OrderedDict
from typing import TextIO

from pyang import plugin


def pyang_plugin_init():
    plugin.register_plugin(YangToRustPlugin())


# ---------------------------------------------------------------------------
# YANG type -> Rust type mapping
# ---------------------------------------------------------------------------

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
    "binary": "String",
    "identityref": "String",
    "union": "String",
    "bits": "String",
    "decimal64": "f64",
    "instance-identifier": "String",
    # common derived types from ietf-yang-types / ietf-inet-types
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

# Sentinel returned by _resolve_type for enumeration leaves.
_ENUM_SENTINEL = "__ENUM__"

_RUST_KEYWORDS = frozenset({
    "as", "break", "const", "continue", "crate", "else", "enum", "extern",
    "false", "fn", "for", "if", "impl", "in", "let", "loop", "match", "mod",
    "move", "mut", "pub", "ref", "return", "self", "static", "struct", "super",
    "trait", "true", "type", "unsafe", "use", "where", "while", "async",
    "await", "dyn", "abstract", "become", "box", "do", "final", "macro",
    "override", "priv", "try", "typeof", "unsized", "virtual", "yield",
})


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _yang_name_to_pascal(name: str) -> str:
    """Convert a kebab-case YANG name to PascalCase."""
    return "".join(part.capitalize() for part in name.split("-"))


def _yang_name_to_snake(name: str) -> str:
    """Convert a kebab-case YANG name to snake_case."""
    return name.replace("-", "_")


def _needs_serde_rename(yang_name: str) -> bool:
    """Return True if the YANG name contains hyphens (differs from snake_case)."""
    return "-" in yang_name


def _is_config_false(stmt) -> bool:
    config = stmt.search_one("config")
    return config is not None and config.arg == "false"


def _should_skip(stmt) -> bool:
    """Return True if a data node should be omitted from generated code."""
    if _is_config_false(stmt):
        return True
    if stmt.keyword in ("notification", "rpc", "action"):
        return True
    return False


def _get_children(stmt):
    """Return the resolved children of *stmt*, filtering out skippable nodes."""
    if not hasattr(stmt, "i_children"):
        return []
    return [ch for ch in stmt.i_children if not _should_skip(ch)]


def _is_presence_container(stmt) -> bool:
    return stmt.keyword == "container" and stmt.search_one("presence") is not None


def _is_mandatory(stmt) -> bool:
    """True when a leaf or container carries ``mandatory true``."""
    m = stmt.search_one("mandatory")
    return m is not None and m.arg == "true"


def _resolve_type(type_stmt) -> str:
    """Map a YANG ``type`` sub-statement to a Rust type string."""
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

    if type_name in _YANG_TO_RUST:
        return _YANG_TO_RUST[type_name]

    # Prefixed type (e.g., inet:host)
    if ":" in type_name:
        unprefixed = type_name.split(":", 1)[1]
        if unprefixed in _YANG_TO_RUST:
            return _YANG_TO_RUST[unprefixed]

    # Walk through typedef chain
    if hasattr(type_stmt, "i_typedef") and type_stmt.i_typedef is not None:
        td_type = type_stmt.i_typedef.search_one("type")
        if td_type is not None:
            return _resolve_type(td_type)

    # i_type_spec base type
    if hasattr(type_stmt, "i_type_spec") and type_stmt.i_type_spec is not None:
        ts = type_stmt.i_type_spec
        if hasattr(ts, "name") and ts.name in _YANG_TO_RUST:
            return _YANG_TO_RUST[ts.name]

    return "String"


def _find_enum_stmts(type_stmt):
    """Find ``enum`` sub-statements, following the typedef chain if needed."""
    if type_stmt is None:
        return []

    # Direct enum children
    enums = type_stmt.search("enum")
    if enums:
        return enums

    # Follow typedef chain
    if hasattr(type_stmt, "i_typedef") and type_stmt.i_typedef is not None:
        td_type = type_stmt.i_typedef.search_one("type")
        if td_type is not None:
            return _find_enum_stmts(td_type)

    return []


def _find_enum_typedef_name(type_stmt) -> str | None:
    """If a type resolves to an enumeration through a named typedef, return
    the typedef name (PascalCase).  Otherwise return None."""
    if type_stmt is None:
        return None
    if type_stmt.arg == "enumeration":
        return None  # inline enumeration, not a typedef
    if hasattr(type_stmt, "i_typedef") and type_stmt.i_typedef is not None:
        td_type = type_stmt.i_typedef.search_one("type")
        if td_type is not None and td_type.arg == "enumeration":
            return _yang_name_to_pascal(type_stmt.i_typedef.arg)
        # Continue following the chain
        if td_type is not None:
            return _find_enum_typedef_name(td_type)
    return None


def _get_description(stmt) -> str | None:
    desc = stmt.search_one("description")
    return desc.arg if desc is not None else None


def _first_doc_line(text: str | None) -> str | None:
    """Return first non-empty line of a description, or None."""
    if not text:
        return None
    for raw in text.strip().split("\n"):
        line = raw.strip()
        if line:
            return line
    return None


def _wrap_doc(text: str) -> list[str]:
    """Return up to three non-empty lines from *text*."""
    lines = []
    for raw in text.strip().split("\n"):
        line = raw.strip()
        lines.append(line if line else "")
        if len(lines) >= 3:
            break
    return lines


def _safe_rust_name(snake: str) -> str:
    """Escape a snake_case identifier if it is a Rust keyword."""
    if snake in _RUST_KEYWORDS:
        return f"r#{snake}"
    return snake


# ---------------------------------------------------------------------------
# Intermediate representations
# ---------------------------------------------------------------------------

class RustField:
    """A single field in a Rust struct."""

    __slots__ = ("yang_name", "rust_name", "rust_type",
                 "optional", "is_vec", "doc")

    def __init__(self, yang_name: str, rust_type: str, *,
                 optional: bool = False, is_vec: bool = False,
                 doc: str | None = None):
        self.yang_name = yang_name
        self.rust_name = _yang_name_to_snake(yang_name)
        self.rust_type = rust_type
        self.optional = optional
        self.is_vec = is_vec
        self.doc = doc

    def type_string(self) -> str:
        t = self.rust_type
        if self.is_vec:
            t = f"Vec<{t}>"
        if self.optional:
            t = f"Option<{t}>"
        return t


class RustStruct:
    __slots__ = ("name", "fields", "doc")

    def __init__(self, name: str, doc: str | None = None):
        self.name = name
        self.fields: list[RustField] = []
        self.doc = doc


class RustEnumVariant:
    __slots__ = ("yang_name", "rust_name", "doc")

    def __init__(self, yang_name: str, doc: str | None = None):
        self.yang_name = yang_name
        self.rust_name = _yang_name_to_pascal(yang_name)
        self.doc = doc


class RustEnum:
    __slots__ = ("name", "variants", "doc")

    def __init__(self, name: str, doc: str | None = None):
        self.name = name
        self.variants: list[RustEnumVariant] = []
        self.doc = doc


# ---------------------------------------------------------------------------
# Collector — walks the resolved YANG data tree
# ---------------------------------------------------------------------------

class Collector:
    def __init__(self):
        self.structs: OrderedDict[str, RustStruct] = OrderedDict()
        self.enums: OrderedDict[str, RustEnum] = OrderedDict()
        self.typedefs: OrderedDict[str, str] = OrderedDict()
        self._used_names: set[str] = set()

    # -- public entry point -------------------------------------------------

    def collect_module(self, module):
        # Typedefs
        for td in module.search("typedef"):
            td_type = td.search_one("type")
            rust_type = _resolve_type(td_type)
            td_pascal = _yang_name_to_pascal(td.arg)
            if rust_type == _ENUM_SENTINEL:
                self._collect_enum_typedef(td)
            else:
                self.typedefs[td_pascal] = rust_type

        # Top-level data nodes
        for child in _get_children(module):
            self._process_node(child, parent_name="")

        # Augmentations (e.g., augment /sys:system)
        for augment in module.search("augment"):
            for child in _get_children(augment):
                self._process_node(child, parent_name="")

    # -- naming helpers -----------------------------------------------------

    def _unique_name(self, desired: str) -> str:
        name = desired
        n = 2
        while name in self._used_names:
            name = f"{desired}{n}"
            n += 1
        self._used_names.add(name)
        return name

    def _struct_name(self, yang_name: str, parent_name: str) -> str:
        """Build a PascalCase struct name, prefixed with *parent_name* when
        the bare name would collide or is too generic."""
        pascal = _yang_name_to_pascal(yang_name)
        # Always prefix with parent when name is very short / generic, or
        # when the bare name is already taken.
        if parent_name and (
            pascal in self._used_names
            or pascal in _GENERIC_NAMES
        ):
            pascal = f"{parent_name}{pascal}"
        return self._unique_name(pascal)

    # -- typedef helpers ----------------------------------------------------

    def _collect_enum_typedef(self, td):
        td_type = td.search_one("type")
        enum_name = _yang_name_to_pascal(td.arg)
        rust_enum = RustEnum(enum_name, _get_description(td))
        for e in td_type.search("enum"):
            rust_enum.variants.append(
                RustEnumVariant(e.arg, _get_description(e))
            )
        if rust_enum.variants:
            self.enums[enum_name] = rust_enum

    # -- main dispatch ------------------------------------------------------

    def _process_node(self, stmt, parent_name: str) -> RustField | None:
        kw = stmt.keyword
        if kw == "container":
            return self._process_container(stmt, parent_name)
        if kw == "list":
            return self._process_list(stmt, parent_name)
        if kw == "leaf":
            return self._process_leaf(stmt, parent_name)
        if kw == "leaf-list":
            return self._process_leaf_list(stmt, parent_name)
        if kw == "choice":
            # Returning None tells the caller to call _flatten_choice.
            return None
        return None

    # -- containers ---------------------------------------------------------

    def _process_container(self, stmt, parent_name: str) -> RustField:
        sname = self._struct_name(stmt.arg, parent_name)
        rs = RustStruct(sname, _get_description(stmt))
        self._fill_children(stmt, rs, sname)
        self.structs[sname] = rs

        is_presence = _is_presence_container(stmt)
        return RustField(
            stmt.arg, sname,
            optional=True,  # containers are always optional in JSON
            doc=_get_description(stmt),
        )

    # -- lists --------------------------------------------------------------

    def _process_list(self, stmt, parent_name: str) -> RustField:
        sname = self._struct_name(stmt.arg, parent_name)
        rs = RustStruct(sname, _get_description(stmt))
        self._fill_children(stmt, rs, sname)
        self.structs[sname] = rs

        return RustField(
            stmt.arg, sname,
            is_vec=True,
            doc=_get_description(stmt),
        )

    # -- leaves -------------------------------------------------------------

    def _process_leaf(self, stmt, parent_name: str) -> RustField:
        type_stmt = stmt.search_one("type")
        rust_type = _resolve_type(type_stmt)

        if rust_type == _ENUM_SENTINEL:
            # Check if this enum comes from a named typedef we can reuse
            td_name = _find_enum_typedef_name(type_stmt)
            if td_name and td_name in self.enums:
                rust_type = td_name
            else:
                enum_name = td_name or self._struct_name(stmt.arg, parent_name)
                if enum_name not in self.enums:
                    enum_name = self._unique_name(enum_name) if enum_name not in self._used_names else enum_name
                    rust_enum = RustEnum(enum_name, _get_description(stmt))
                    for e in _find_enum_stmts(type_stmt):
                        rust_enum.variants.append(
                            RustEnumVariant(e.arg, _get_description(e))
                        )
                    self.enums[enum_name] = rust_enum
                rust_type = enum_name

        optional = self._leaf_is_optional(stmt)
        return RustField(
            stmt.arg, rust_type,
            optional=optional,
            doc=_get_description(stmt),
        )

    def _process_leaf_list(self, stmt, parent_name: str) -> RustField:
        type_stmt = stmt.search_one("type")
        rust_type = _resolve_type(type_stmt)
        if rust_type == _ENUM_SENTINEL:
            rust_type = "String"

        return RustField(
            stmt.arg, rust_type,
            is_vec=True,
            doc=_get_description(stmt),
        )

    @staticmethod
    def _leaf_is_optional(stmt) -> bool:
        """A leaf is optional unless it is mandatory, has a default, or is a
        list key."""
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

    # -- choice / case ------------------------------------------------------

    def _flatten_choice(self, choice_stmt, parent_name: str) -> list[RustField]:
        """Flatten all case branches into ``Option<T>`` fields."""
        fields: list[RustField] = []
        cases = [ch for ch in _get_children(choice_stmt)
                 if ch.keyword == "case"]
        if not cases:
            cases = [choice_stmt]

        for case in cases:
            for child in _get_children(case):
                if child.keyword == "choice":
                    fields.extend(self._flatten_choice(child, parent_name))
                else:
                    field = self._process_node(child, parent_name)
                    if field is not None:
                        field.optional = True
                        fields.append(field)
        return fields

    # -- children -----------------------------------------------------------

    def _fill_children(self, stmt, rs: RustStruct, sname: str):
        """Populate *rs* fields from the children of *stmt*."""
        for child in _get_children(stmt):
            if child.keyword == "choice":
                rs.fields.extend(self._flatten_choice(child, sname))
            else:
                field = self._process_node(child, sname)
                if field is not None:
                    rs.fields.append(field)


# Very short / generic container names that should be prefixed with their
# parent to avoid ambiguity.
_GENERIC_NAMES = frozenset({
    "InlineDefinition", "CentralKeystoreReference",
    "CentralTruststoreReference", "Certificate", "Server",
    "EncryptedBy", "EncryptedPrivateKey", "EncryptedSymmetricKey",
    "TlsVersions", "CipherSuites", "HelloParams",
    "ClientIdentity", "ServerAuthentication",
    "CaCerts", "EeCerts", "RawPublicKeys",
    "InlineOrKeystore", "InlineOrTruststore",
    "PublicKey",
})


# ---------------------------------------------------------------------------
# Emitter
# ---------------------------------------------------------------------------

class RustEmitter:
    def __init__(self, fd: TextIO, collector: Collector):
        self.fd = fd
        self.c = collector

    def emit(self):
        self._header()
        self._typedefs()
        self._enums()
        self._structs()

    # -- sections -----------------------------------------------------------

    def _header(self):
        w = self.fd.write
        w("// Auto-generated from YANG modules by yang2rust.py -- DO NOT EDIT\n\n")
        w("#![allow(dead_code)]\n\n")
        w("use serde::Deserialize;\n\n")

    def _typedefs(self):
        if not self.c.typedefs:
            return
        self.fd.write("// --- Type aliases (from YANG typedefs) ---\n\n")
        for name, rust_type in self.c.typedefs.items():
            self.fd.write(f"pub type {name} = {rust_type};\n")
        self.fd.write("\n")

    def _enums(self):
        if not self.c.enums:
            return
        self.fd.write("// --- Enums (from YANG enumerations) ---\n\n")
        for enum in self.c.enums.values():
            self._emit_doc(enum.doc, indent="")
            self.fd.write("#[derive(Debug, Clone, Deserialize)]\n")
            self.fd.write(f"pub enum {enum.name} {{\n")
            for v in enum.variants:
                self._emit_doc(v.doc, indent="    ", max_lines=1)
                if v.yang_name != v.rust_name:
                    self.fd.write(f'    #[serde(rename = "{v.yang_name}")]\n')
                self.fd.write(f"    {v.rust_name},\n")
            self.fd.write("}\n\n")

    def _structs(self):
        if not self.c.structs:
            return
        self.fd.write("// --- Structs (from YANG containers / lists) ---\n\n")
        for st in self.c.structs.values():
            self._emit_doc(st.doc, indent="")
            self.fd.write("#[derive(Debug, Clone, Deserialize)]\n")
            self.fd.write('#[serde(rename_all = "kebab-case")]\n')
            self.fd.write(f"pub struct {st.name} {{\n")
            for f in st.fields:
                self._emit_field(f)
            self.fd.write("}\n\n")

    # -- field emission -----------------------------------------------------

    def _emit_field(self, f: RustField):
        w = self.fd.write
        first = _first_doc_line(f.doc)
        if first:
            w(f"    /// {first}\n")

        if _needs_serde_rename(f.yang_name):
            w(f'    #[serde(rename = "{f.yang_name}")]\n')

        if f.optional or f.is_vec:
            w("    #[serde(default)]\n")

        name = _safe_rust_name(f.rust_name)
        w(f"    pub {name}: {f.type_string()},\n")

    # -- doc helpers --------------------------------------------------------

    def _emit_doc(self, text: str | None, indent: str = "",
                  max_lines: int = 3):
        if not text:
            return
        for i, line in enumerate(_wrap_doc(text)):
            if i >= max_lines:
                break
            self.fd.write(f"{indent}/// {line}\n")


# ---------------------------------------------------------------------------
# Plugin class
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
        collector = Collector()
        for module in modules:
            collector.collect_module(module)
        RustEmitter(fd, collector).emit()
