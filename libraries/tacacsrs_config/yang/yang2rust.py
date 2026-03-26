"""pyang plugin that generates Rust struct/enum definitions from YANG modules.

Types are grouped into Rust modules matching their originating YANG module,
so ietf-keystore groupings produce ``keystore::InlineDefinition`` rather
than a flattened ``TacacsPlusServerCertificateInlineDefinition``.

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

_ENUM_SENTINEL = "__ENUM__"

_RUST_KEYWORDS = frozenset({
    "as", "break", "const", "continue", "crate", "else", "enum", "extern",
    "false", "fn", "for", "if", "impl", "in", "let", "loop", "match", "mod",
    "move", "mut", "pub", "ref", "return", "self", "static", "struct", "super",
    "trait", "true", "type", "unsafe", "use", "where", "while", "async",
    "await", "dyn", "abstract", "become", "box", "do", "final", "macro",
    "override", "priv", "try", "typeof", "unsized", "virtual", "yield",
})

# YANG module name -> Rust module name
_MODULE_MAP = {
    "ietf-crypto-types": "crypto_types",
    "ietf-keystore": "keystore",
    "ietf-truststore": "truststore",
    "ietf-tls-common": "tls_common",
    "ietf-tls-client": "tls_client",
    "ietf-system-tacacs-plus": "tacacs_plus",
    "ietf-netconf-acm": "nacm",
}

# Modules whose types we skip entirely (just primitives/typedefs)
_SKIP_MODULES = frozenset({
    "ietf-inet-types", "ietf-yang-types", "ietf-system",
    "ietf-interfaces", "ietf-network-instance",
})


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


def _doc_lines(text: str, max_lines: int = 3) -> list[str]:
    lines = []
    for raw in text.strip().split("\n"):
        lines.append(raw.strip())
        if len(lines) >= max_lines:
            break
    return lines


def _source_module(stmt) -> str | None:
    """Return the YANG module name that originally defined this node."""
    if hasattr(stmt, "i_orig_module") and stmt.i_orig_module is not None:
        return stmt.i_orig_module.arg
    if hasattr(stmt, "i_module") and stmt.i_module is not None:
        return stmt.i_module.arg
    return None


# Map from YANG grouping name to a short, clean PascalCase prefix.
# The grouping names are verbose (e.g. "inline-or-keystore-end-entity-cert-
# with-key-grouping"), so we map them to concise prefixes.
_GROUPING_PREFIX_MAP = {
    # ietf-keystore groupings
    "inline-or-keystore-end-entity-cert-with-key-grouping": "EndEntityCertWithKey",
    "inline-or-keystore-asymmetric-key-grouping": "AsymmetricKey",
    "inline-or-keystore-symmetric-key-grouping": "SymmetricKey",
    # ietf-truststore groupings
    "inline-or-truststore-certs-grouping": "Certs",
    "inline-or-truststore-public-keys-grouping": "PublicKeys",
    # ietf-crypto-types groupings
    "private-key-grouping": "PrivateKey",
    "symmetric-key-grouping": "SymmetricKey",
    "encrypted-value-grouping": "EncryptedValue",
    # ietf-tls-common groupings
    "hello-params-grouping": "HelloParams",
    # ietf-tls-client groupings
    "tls-client-grouping": "TlsClient",
}


def _grouping_prefix(stmt) -> str:
    """Derive a PascalCase prefix from the nearest YANG grouping name.
    
    Returns an empty string if no grouping context is available.
    """
    if not hasattr(stmt, "i_uses") or not stmt.i_uses:
        return ""
    # The last uses statement in the chain is the nearest grouping.
    last_uses = stmt.i_uses[-1]
    grp_name = last_uses.arg
    # Strip module prefix (e.g. "ks:inline-or-keystore-..." -> "inline-or-...")
    if ":" in grp_name:
        grp_name = grp_name.split(":", 1)[1]
    # Check our curated mapping first
    if grp_name in _GROUPING_PREFIX_MAP:
        return _GROUPING_PREFIX_MAP[grp_name]
    # Fallback: convert the grouping name directly, stripping "-grouping"
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


# ---------------------------------------------------------------------------
# Intermediate representations
# ---------------------------------------------------------------------------

class Field:
    __slots__ = ("yang_name", "rust_name", "rust_type", "optional",
                 "is_vec", "doc")

    def __init__(self, yang_name, rust_type, *, optional=False,
                 is_vec=False, doc=None):
        self.yang_name = yang_name
        self.rust_name = _yang_to_snake(yang_name)
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


class Struct:
    __slots__ = ("name", "fields", "doc", "choices")

    def __init__(self, name, doc=None):
        self.name = name
        self.fields: list[Field] = []
        self.choices: list[ChoiceGroup] = []
        self.doc = doc


class ChoiceGroup:
    """Metadata about a YANG choice node flattened into a struct."""
    __slots__ = ("yang_name", "mandatory", "cases")

    def __init__(self, yang_name: str, mandatory: bool):
        self.yang_name = yang_name
        self.mandatory = mandatory
        # Each case is (case_yang_name, [field_yang_names])
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


class ModuleTypes:
    """Collected types for one YANG module."""

    def __init__(self, yang_name: str, rust_name: str):
        self.yang_name = yang_name
        self.rust_name = rust_name
        self.structs: OrderedDict[str, Struct] = OrderedDict()
        self.enums: OrderedDict[str, Enum] = OrderedDict()
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
# Collector — walks the resolved YANG data tree, groups by source module
# ---------------------------------------------------------------------------

class Collector:
    def __init__(self):
        self.modules: OrderedDict[str, ModuleTypes] = OrderedDict()
        # Fingerprint -> (module_name, struct_name) for deduplication
        self._fingerprints: dict[str, tuple[str, str]] = {}

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

        # Typedefs
        for td in module.search("typedef"):
            td_type = td.search_one("type")
            rust_type = _resolve_type(td_type)
            td_pascal = _yang_to_pascal(td.arg)
            mod = self._get_mod(module.arg)
            if rust_type == _ENUM_SENTINEL:
                self._collect_enum_typedef(td, mod)
            else:
                mod.typedefs[td_pascal] = rust_type

        # Top-level data nodes
        for child in _get_children(module):
            self._process_node(child, parent_prefix="")

        # Augmentations
        for augment in module.search("augment"):
            for child in _get_children(augment):
                self._process_node(child, parent_prefix="")

    def _collect_enum_typedef(self, td, mod: ModuleTypes):
        td_type = td.search_one("type")
        enum_name = _yang_to_pascal(td.arg)
        rust_enum = Enum(enum_name, _get_desc(td))
        for e in td_type.search("enum"):
            rust_enum.variants.append(EnumVariant(e.arg, _get_desc(e)))
        if rust_enum.variants:
            mod.enums[enum_name] = rust_enum

    # -- naming within a module ---

    def _struct_name(self, stmt, parent_prefix: str) -> tuple[ModuleTypes, str, bool]:
        """Return (module, name, already_existed) for a container/list struct.
        
        Uses structural fingerprinting to deduplicate: if a node from the
        same YANG module has the same children structure as one we've already
        emitted, reuse the existing struct name instead of creating a new one.
        
        Names are derived from the YANG **grouping name** when available,
        producing names like ``keystore::AsymmetricKeyInlineDefinition``
        instead of ``keystore::ClientCredentialsCertificateInlineDefinition``.
        """
        mod = self._mod_for_stmt(stmt)
        fp = self._fingerprint(stmt)

        # Check if we've already emitted a struct with this exact structure
        # in the same module.
        fp_key = f"{mod.yang_name}:{fp}"
        if fp_key in self._fingerprints:
            existing_mod_name, existing_name = self._fingerprints[fp_key]
            return mod, existing_name, True

        pascal = _yang_to_pascal(stmt.arg)

        # Derive a context prefix from the nearest YANG grouping name
        # instead of the usage-site parent. This produces meaningful names
        # like ``AsymmetricKeyInlineDefinition`` instead of
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
        """Create a structural fingerprint of a container/list node.
        
        Two nodes with the same fingerprint have identical children
        structure (same leaf names, types, and nested container shapes).
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
                # Recurse for shape (but limit depth to avoid explosion)
                sub_fp = Collector._fingerprint(ch)
                parts.append(f"C:{ch.arg}:{sub_fp}")
            elif ch.keyword == "choice":
                sub_fp = Collector._fingerprint(ch)
                parts.append(f"CH:{ch.arg}:{sub_fp}")
            elif ch.keyword == "case":
                sub_fp = Collector._fingerprint(ch)
                parts.append(f"CA:{ch.arg}:{sub_fp}")
        return "|".join(parts)

    # -- main dispatch ---

    def _process_node(self, stmt, parent_prefix: str) -> Field | None:
        kw = stmt.keyword
        if kw == "container":
            return self._process_container(stmt, parent_prefix)
        if kw == "list":
            return self._process_list(stmt, parent_prefix)
        if kw == "leaf":
            return self._process_leaf(stmt, parent_prefix)
        if kw == "leaf-list":
            return self._process_leaf_list(stmt, parent_prefix)
        if kw == "choice":
            return None  # caller uses _flatten_choice
        return None

    def _process_container(self, stmt, parent_prefix: str) -> Field:
        mod, sname, existed = self._struct_name(stmt, parent_prefix)
        if not existed:
            rs = Struct(sname, _get_desc(stmt))
            self._fill_children(stmt, rs, sname)
            mod.structs[sname] = rs

        type_ref = self._qualified_type(stmt, sname)
        return Field(stmt.arg, type_ref, optional=True, doc=_get_desc(stmt))

    def _process_list(self, stmt, parent_prefix: str) -> Field:
        mod, sname, existed = self._struct_name(stmt, parent_prefix)
        if not existed:
            rs = Struct(sname, _get_desc(stmt))
            self._fill_children(stmt, rs, sname)
            mod.structs[sname] = rs

        type_ref = self._qualified_type(stmt, sname)
        return Field(stmt.arg, type_ref, is_vec=True, doc=_get_desc(stmt))

    def _process_leaf(self, stmt, parent_prefix: str) -> Field:
        type_stmt = stmt.search_one("type")
        rust_type = _resolve_type(type_stmt)

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

        optional = _leaf_is_optional(stmt)
        return Field(stmt.arg, rust_type, optional=optional, doc=_get_desc(stmt))

    def _process_leaf_list(self, stmt, parent_prefix: str) -> Field:
        type_stmt = stmt.search_one("type")
        rust_type = _resolve_type(type_stmt)
        if rust_type == _ENUM_SENTINEL:
            rust_type = "String"
        return Field(stmt.arg, rust_type, is_vec=True, doc=_get_desc(stmt))

    def _flatten_choice(self, choice_stmt, parent_prefix: str) -> tuple[list[Field], ChoiceGroup]:
        """Flatten all case branches into ``Option<T>`` fields and record choice metadata."""
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
                    # Nested choice — recurse and merge
                    nested_fields, nested_group = self._flatten_choice(child, parent_prefix)
                    fields.extend(nested_fields)
                    # Attach nested choice as a separate group
                    choice_group.cases.append((
                        f"{case.arg}/{child.arg}",
                        [f.yang_name for f in nested_fields],
                    ))
                else:
                    field = self._process_node(child, parent_prefix)
                    if field is not None:
                        field.optional = True
                        fields.append(field)
                        case_field_names.append(field.yang_name)
            if case_field_names:
                choice_group.cases.append((case.arg, case_field_names))

        return fields, choice_group

    def _fill_children(self, stmt, rs: Struct, sname: str):
        for child in _get_children(stmt):
            if child.keyword == "choice":
                choice_fields, choice_group = self._flatten_choice(child, sname)
                rs.fields.extend(choice_fields)
                if choice_group.cases:
                    rs.choices.append(choice_group)
            else:
                field = self._process_node(child, sname)
                if field is not None:
                    rs.fields.append(field)

    def _qualified_type(self, stmt, local_name: str) -> str:
        """Return a type reference, qualified with module:: if cross-module."""
        src = _source_module(stmt)
        if not src or src in _SKIP_MODULES:
            src = self._current_top_module
        src_rust = _MODULE_MAP.get(src, _yang_to_snake(src))
        top_rust = _MODULE_MAP.get(self._current_top_module,
                                   _yang_to_snake(self._current_top_module))
        # If the type lives in a different Rust module than the struct
        # that references it, qualify it.
        # For now, always qualify — the emitter wraps each module, so
        # self-references within the same module use just the name.
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
# Emitter — writes Rust modules
# ---------------------------------------------------------------------------

class RustEmitter:
    def __init__(self, fd: TextIO, collector: Collector):
        self.fd = fd
        self.c = collector

    def emit(self):
        w = self.fd.write
        w("// Auto-generated from YANG modules by yang2rust.py — DO NOT EDIT\n\n")
        w("#![allow(dead_code)]\n\n")

        # Emit each module
        for mod in self.c.modules.values():
            if not mod.structs and not mod.enums and not mod.typedefs:
                continue
            self._emit_module(mod)

    def _emit_module(self, mod: ModuleTypes):
        w = self.fd.write

        w(f"/// Types from `{mod.yang_name}`.\n")
        w(f"pub mod {mod.rust_name} {{\n")
        w("    use serde::Deserialize;\n")

        # Compute which other modules we need to import
        imports = set()
        for st in mod.structs.values():
            for f in st.fields:
                if "::" in f.rust_type:
                    foreign_mod = f.rust_type.split("::")[0]
                    if foreign_mod != mod.rust_name:
                        imports.add(foreign_mod)
        for imp in sorted(imports):
            w(f"    use super::{imp};\n")
        w("\n")

        # Typedefs
        for name, rt in mod.typedefs.items():
            w(f"    pub type {name} = {rt};\n")
        if mod.typedefs:
            w("\n")

        # Enums
        for enum in mod.enums.values():
            self._emit_enum(enum)

        # Structs
        for st in mod.structs.values():
            self._emit_struct(st, mod.rust_name)

        self.fd.write("}\n\n")

    def _emit_enum(self, enum: Enum):
        w = self.fd.write
        self._doc(enum.doc, "    ")
        w("    #[derive(Debug, Clone, Deserialize)]\n")
        w(f"    pub enum {enum.name} {{\n")
        for v in enum.variants:
            self._doc(v.doc, "        ", max_lines=1)
            if v.yang_name != _yang_to_snake(v.rust_name):
                w(f'        #[serde(rename = "{v.yang_name}")]\n')
            w(f"        {v.rust_name},\n")
        w("    }\n\n")

    def _emit_struct(self, st: Struct, current_mod: str):
        w = self.fd.write
        self._doc(st.doc, "    ")
        w("    #[derive(Debug, Clone, Deserialize)]\n")
        w('    #[serde(rename_all = "kebab-case")]\n')
        w(f"    pub struct {st.name} {{\n")
        for f in st.fields:
            self._emit_field(f, current_mod)
        w("    }\n\n")

        # Emit choice group constants if this struct has flattened choices
        if st.choices:
            self._emit_choice_constants(st)

    def _emit_field(self, f: Field, current_mod: str):
        w = self.fd.write
        first = _first_line(f.doc)
        if first:
            w(f"        /// {first}\n")

        if _needs_rename(f.yang_name):
            w(f'        #[serde(rename = "{f.yang_name}")]\n')

        if f.optional or f.is_vec:
            w("        #[serde(default)]\n")

        # Resolve type reference: strip own module prefix for local types
        type_str = f.type_string()
        own_prefix = f"{current_mod}::"
        type_str = type_str.replace(own_prefix, "")

        name = _safe_name(f.rust_name)
        w(f"        pub {name}: {type_str},\n")

    def _doc(self, text, indent, max_lines=3):
        if not text:
            return
        for i, line in enumerate(_doc_lines(text, max_lines)):
            if i >= max_lines:
                break
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
