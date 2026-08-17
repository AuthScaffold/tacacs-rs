#!/usr/bin/env python3
"""Expand the ietf-system-tacacs-plus YANG module into a resolved tree.

The script gets the required YANG modules from a pinned repository. It uses
the cached repository if it is available. The script also includes the
project-owned YANG modules from ``modules/``. Then pyang resolves all grouping
references and generates the expanded tree.

The script can also generate a pyang-compatible feature vector. The vector
contains features from the TACACS+ module and its imported TLS modules.
Disable a feature to remove its feature-gated nodes from the tree.

Prerequisites:
    Install pyang in an active virtual environment or in the global environment:
        python -m pip install -r requirements.txt

Usage:
    python expand_yang_tree.py                  # Writes to stdout.
    python expand_yang_tree.py -o tree.txt      # Writes to a file.
    python expand_yang_tree.py --format jstree  # Uses another pyang format.
    python expand_yang_tree.py --list-features  # Writes a feature vector.
    python expand_yang_tree.py --list-features --list-features-format ini
                                              # Writes an editable INI manifest.
    python expand_yang_tree.py --features-ini feature-flags.ini
                                              # Disables entries with false values.
    python expand_yang_tree.py -f rust \
        --features-ini feature-flags.ini       # Runs the custom Rust plug-in.
"""

from __future__ import annotations

import argparse
import configparser
import os
import re
import shutil
import stat
import subprocess
import sys
import textwrap
from collections.abc import Callable
from pathlib import Path

from pyang import context
from pyang import repository
from pyang import syntax
from pyang import util

YANG_MODELS_REPO = "https://github.com/YangModels/yang.git"
YANG_MODELS_COMMIT = "97ca2414920c0de09171327b84aa11395f79e284"

TACACS_ROOT_MODULE = "ietf-system-tacacs-plus"
TACACS_MODULE = "ietf-system-tacacs-plus@2026-03-31.yang"

SCRIPT_DIR = Path(__file__).resolve().parent
CACHE_ROOT = SCRIPT_DIR / ".yang-cache"
CACHE_DIR = CACHE_ROOT / sys.platform
PLUGIN_DIR = SCRIPT_DIR / "plugins"
LOCAL_YANG_DIR = SCRIPT_DIR / "modules"

TREE_FEATURE_GROUP_RE = re.compile(r"\{([^{}]+)\}\?")


def _run(args: list[str], **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(args, check=True, capture_output=True, text=True, **kwargs)


def _remove_readonly(
    function: Callable[[str], object],
    path: str,
    _exc_info: object,
) -> None:
    os.chmod(path, stat.S_IWRITE)
    function(path)


def clean_cache() -> None:
    if CACHE_DIR.exists():
        shutil.rmtree(CACHE_DIR, onerror=_remove_readonly)


def _local_yang_modules() -> list[Path]:
    if not LOCAL_YANG_DIR.exists():
        return []
    return sorted(LOCAL_YANG_DIR.glob("*.yang"))


def _load_pyang_modules(root_module_name: str, search_paths: list[Path], module_paths: list[Path]) -> tuple[object, dict[str, object], dict[str, set[str]]]:
    repository_path = os.pathsep.join(str(path) for path in search_paths)
    repo = repository.FileRepository(repository_path)
    ctx = context.Context(repo)

    for module_path in module_paths:
        try:
            module_text = module_path.read_text(encoding="utf-8")
        except OSError as exc:
            raise OSError(f"The script did not read the local YANG module {module_path}") from exc
        ctx.add_module(str(module_path), module_text)

    root_module = ctx.search_module(None, root_module_name)
    if root_module is None:
        raise ValueError(f"The script did not load the root module '{root_module_name}'")

    ctx.validate()

    modules_by_name: dict[str, object] = {}
    for module in ctx.modules.values():
        if module is None or module.keyword != "module":
            continue
        modules_by_name[module.i_modulename] = module

    feature_index: dict[str, set[str]] = {}
    for module_name, module in modules_by_name.items():
        for feature_name in module.i_features:
            feature_index.setdefault(feature_name, set()).add(module_name)

    return root_module, modules_by_name, feature_index


def _main_module(module_or_stmt: object) -> object:
    if getattr(module_or_stmt, "keyword", None) == "module":
        return module_or_stmt

    module = getattr(module_or_stmt, "i_module", None)
    if module is None or module.keyword == "module":
        return module

    return module.main_module()


def _extract_feature_refs_from_expr(expression: object) -> set[str]:
    if isinstance(expression, str):
        return {expression}

    operator = expression[0]
    refs = _extract_feature_refs_from_expr(expression[1])
    if operator != "not":
        refs.update(_extract_feature_refs_from_expr(expression[2]))
    return refs


def _resolve_feature_ref(base_stmt: object, feature_ref: str) -> tuple[str, str]:
    prefix, feature_name = util.split_identifier(feature_ref)
    if prefix is None or prefix == base_stmt.i_module.i_prefix:
        module = _main_module(base_stmt)
    else:
        module = util.prefix_to_module(base_stmt.i_module, prefix, base_stmt.pos, [])
        if module is None:
            raise ValueError(f"Unknown prefix '{prefix}' in feature reference '{feature_ref}'")
        module = _main_module(module)

    return module.i_modulename, feature_name


def _resolve_prefixed_tree_feature_ref(
    feature_ref: str,
    root_module: object,
    loaded_modules: dict[str, object],
) -> tuple[str, str]:
    prefix, feature_name = feature_ref.split(":", 1)

    if prefix == root_module.i_prefix:
        return root_module.i_modulename, feature_name

    imported_module = util.prefix_to_module(root_module, prefix, root_module.pos, [])
    if imported_module is not None:
        return _main_module(imported_module).i_modulename, feature_name

    for module in loaded_modules.values():
        if module.i_prefix == prefix:
            return module.i_modulename, feature_name

    raise ValueError(f"Unknown prefix '{prefix}' in tree feature reference '{feature_ref}'")


def _get_feature_dependencies(feature_stmt: object) -> set[tuple[str, str]]:
    dependencies: set[tuple[str, str]] = set()
    for if_feature_stmt in feature_stmt.search("if-feature"):
        expression = syntax.parse_if_feature_expr(if_feature_stmt.arg)
        for feature_ref in _extract_feature_refs_from_expr(expression):
            dependencies.add(_resolve_feature_ref(if_feature_stmt, feature_ref))
    return dependencies


def _follow_feature_dependencies(
    seed_refs: list[tuple[str, str]],
    loaded_modules: dict[str, object],
    root_module_name: str,
) -> dict[str, list[str]]:
    pending = list(seed_refs)
    seen: set[tuple[str, str]] = set()
    feature_vector: dict[str, set[str]] = {}

    while pending:
        module_name, feature_name = pending.pop(0)
        if (module_name, feature_name) in seen:
            continue

        seen.add((module_name, feature_name))
        feature_vector.setdefault(module_name, set()).add(feature_name)

        module = loaded_modules.get(module_name)
        if module is None:
            continue

        feature_stmt = module.i_features.get(feature_name)
        if feature_stmt is None:
            continue

        pending.extend(sorted(_get_feature_dependencies(feature_stmt)))

    ordered_modules = sorted(feature_vector, key=lambda module_name: (module_name != root_module_name, module_name))
    return {module_name: sorted(feature_vector[module_name]) for module_name in ordered_modules}


def discover_feature_vector_from_tree_text(root_module: object, loaded_modules: dict[str, object], feature_index: dict[str, set[str]], tree_text: str) -> dict[str, list[str]]:
    seed_refs: set[tuple[str, str]] = set()

    for match in TREE_FEATURE_GROUP_RE.findall(tree_text):
        for raw_token in match.split(","):
            feature_ref = raw_token.strip()
            if not feature_ref:
                continue

            if ":" in feature_ref:
                seed_refs.add(_resolve_prefixed_tree_feature_ref(feature_ref, root_module, loaded_modules))
                continue

            for module_name in feature_index.get(feature_ref, set()):
                seed_refs.add((module_name, feature_ref))

    return _follow_feature_dependencies(list(seed_refs), loaded_modules, root_module.i_modulename)


def format_feature_vector(feature_vector: dict[str, list[str]]) -> str:
    return "\n".join(f"{module_name}:{','.join(features)}" for module_name, features in feature_vector.items())


def _normalize_description(description: str) -> str:
    return " ".join(line.strip() for line in description.splitlines()).strip()


def format_feature_ini(feature_vector: dict[str, list[str]], loaded_modules: dict[str, object]) -> str:
    lines = [
        "# Generated by expand_yang_tree.py --list-features --list-features-format ini",
        "# Toggle entries between true and false as needed.",
        "# Section names are pyang module names.",
    ]

    for module_name, features in feature_vector.items():
        lines.append("")
        lines.append(f"[{module_name}]")

        module = loaded_modules[module_name]
        for feature_name in features:
            feature_stmt = module.i_features.get(feature_name)
            if feature_stmt is not None:
                description_stmt = feature_stmt.search_one("description")
                if description_stmt is not None and description_stmt.arg:
                    normalized_description = _normalize_description(description_stmt.arg)
                    for wrapped_line in textwrap.wrap(normalized_description, width=88):
                        lines.append(f"# {wrapped_line}")
            lines.append(f"{feature_name} = true")
            lines.append("")

        if lines[-1] == "":
            lines.pop()

    return "\n".join(lines)


def parse_feature_ini(feature_ini_path: Path, loaded_modules: dict[str, object]) -> dict[str, list[str]]:
    parser = configparser.ConfigParser(interpolation=None)
    parser.optionxform = str
    parser.read(feature_ini_path, encoding="utf-8")

    disabled_features: dict[str, list[str]] = {}

    for module_name in parser.sections():
        module = loaded_modules.get(module_name)
        if module is None:
            raise ValueError(f"Unknown module '{module_name}' in feature INI file {feature_ini_path}")

        module_disabled: list[str] = []
        for feature_name, raw_value in parser.items(module_name):
            if feature_name not in module.i_features:
                raise ValueError(
                    f"Unknown feature '{feature_name}' in module '{module_name}' "
                    f"in feature INI file {feature_ini_path}"
                )

            try:
                enabled = parser.getboolean(module_name, feature_name)
            except ValueError as exc:
                raise ValueError(
                    f"Invalid Boolean value '{raw_value}' for feature '{feature_name}' "
                    f"in module '{module_name}'"
                ) from exc

            if not enabled:
                module_disabled.append(feature_name)

        if module_disabled:
            disabled_features[module_name] = sorted(module_disabled)

    return disabled_features


def write_output(content: str, output_path: Path | None) -> None:
    if output_path:
        output_path.write_text(content, encoding="utf-8")
        print(f"Wrote output to {output_path}", file=sys.stderr)
    else:
        print(content)


def _verify_repo_revision(repo_path: Path, expected_commit: str) -> None:
    actual_commit = _run(["git", "rev-parse", "HEAD"], cwd=str(repo_path)).stdout.strip()
    if actual_commit != expected_commit:
        raise RuntimeError(
            f"The cached repository {repo_path} is at commit {actual_commit}. "
            f"The expected commit is {expected_commit}. Run again with --clean to refresh the cache."
        )

    symbolic_head = subprocess.run(
        ["git", "symbolic-ref", "-q", "HEAD"],
        cwd=str(repo_path),
        capture_output=True,
        text=True,
    )
    if symbolic_head.returncode == 0:
        raise RuntimeError(
            f"The cached repository {repo_path} is attached to {symbolic_head.stdout.strip()}. "
            "The repository must have a detached HEAD. Run again with --clean."
        )
    if symbolic_head.returncode != 1:
        raise RuntimeError(f"The script did not inspect the cached repository HEAD at {repo_path}")


def ensure_repo(
    url: str,
    name: str,
    commit: str,
    sparse_paths: list[str] | None = None,
) -> Path:
    """Clone an exact revision into the cache and make sure that HEAD is detached."""
    dest = CACHE_DIR / name
    if dest.exists():
        _verify_repo_revision(dest, commit)
        return dest

    CACHE_DIR.mkdir(parents=True, exist_ok=True)

    if sparse_paths:
        _run(["git", "clone", "--filter=blob:none", "--sparse", "--no-checkout", url, str(dest)])
        _run(["git", "sparse-checkout", "set"] + sparse_paths, cwd=str(dest))
    else:
        _run(["git", "clone", "--filter=blob:none", "--no-checkout", url, str(dest)])

    _run(["git", "fetch", "--depth", "1", "origin", commit], cwd=str(dest))
    _run(["git", "checkout", "--detach", commit], cwd=str(dest))
    _verify_repo_revision(dest, commit)

    return dest


def find_pyang() -> str:
    """Return the pyang executable path, or stop with an error."""
    pyang = shutil.which("pyang")
    if pyang is None:
        print(
            "error: pyang was not found on PATH. Install it in the active virtual "
            "environment or the global environment: python -m pip install pyang",
            file=sys.stderr,
        )
        sys.exit(1)
    return pyang


def _append_search_path_args(cmd: list[str], search_paths: list[Path]) -> None:
    for search_path in search_paths:
        cmd.extend(["-p", str(search_path)])


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("-o", "--output", type=Path, default=None, help="Write output to a file instead of stdout")
    parser.add_argument("-f", "--format", default="tree", help="Set the pyang output format (default: tree)")
    parser.add_argument("--depth", type=int, default=20, help="Set the tree depth limit (default: 20)")
    parser.add_argument(
        "--list-features",
        action="store_true",
        help="Write a pyang-compatible feature vector for the TACACS+ module and stop",
    )
    parser.add_argument(
        "--list-features-format",
        choices=("vector", "ini"),
        default="vector",
        help="Set the output format for --list-features (default: vector)",
    )
    parser.add_argument(
        "--features",
        action="append",
        default=[],
        metavar="MODULE:FEATURE[,FEATURE...]",
        help="Run pyang with only the listed module features. You can repeat this option.",
    )
    parser.add_argument(
        "--exclude-features",
        action="append",
        default=[],
        metavar="MODULE:FEATURE[,FEATURE...]",
        help="Run pyang without the listed module features. You can repeat this option.",
    )
    parser.add_argument(
        "--features-ini",
        type=Path,
        default=None,
        help="Read feature Boolean values from an INI manifest. A false value disables the feature.",
    )
    parser.add_argument("--clean", action="store_true", help="Remove and clone the cached repositories again")
    args = parser.parse_args()

    if args.clean and CACHE_DIR.exists():
        clean_cache()
        print(f"Removed the cache directory: {CACHE_DIR}", file=sys.stderr)

    # Get the required repositories.
    print("The script gets the YANG modules. It uses the cache after the first run.", file=sys.stderr)
    yang_models = ensure_repo(
        YANG_MODELS_REPO,
        "yang-models",
        YANG_MODELS_COMMIT,
        sparse_paths=["standard/ietf/RFC"],
    )

    # Create the search paths.
    rfc_yang_dir = yang_models / "standard" / "ietf" / "RFC"

    tacacs_module = rfc_yang_dir / TACACS_MODULE
    if not tacacs_module.exists():
        print(f"error: The TACACS+ YANG module was not found: {tacacs_module}", file=sys.stderr)
        sys.exit(1)

    local_yang_modules = _local_yang_modules()
    search_paths = [rfc_yang_dir]
    if local_yang_modules:
        search_paths.append(LOCAL_YANG_DIR)
    input_modules = [tacacs_module] + local_yang_modules

    if args.list_features:
        if args.features_ini is not None:
            print("error: Do not use --features-ini with --list-features", file=sys.stderr)
            sys.exit(2)

        root_module, loaded_modules, feature_index = _load_pyang_modules(
            TACACS_ROOT_MODULE,
            search_paths,
            local_yang_modules,
        )

        pyang = find_pyang()
        tree_cmd = [
            pyang,
            "-f", "tree",
            "--tree-depth", str(args.depth),
        ]
        _append_search_path_args(tree_cmd, search_paths)
        tree_cmd.extend(str(module_path) for module_path in input_modules)
        if PLUGIN_DIR.exists():
            tree_cmd.extend(["--plugindir", str(PLUGIN_DIR)])
        tree_result = subprocess.run(tree_cmd, capture_output=True, text=True)
        if tree_result.returncode != 0:
            if tree_result.stderr:
                print(tree_result.stderr, file=sys.stderr)
            print(f"pyang stopped with exit code {tree_result.returncode}", file=sys.stderr)
            sys.exit(tree_result.returncode)

        feature_vector = discover_feature_vector_from_tree_text(
            root_module,
            loaded_modules,
            feature_index,
            tree_result.stdout,
        )
        if args.list_features_format == "ini":
            feature_output = format_feature_ini(feature_vector, loaded_modules)
        else:
            feature_output = format_feature_vector(feature_vector)

        write_output(feature_output, args.output)
        return

    pyang = find_pyang()

    ini_disabled_features: dict[str, list[str]] = {}
    if args.features_ini is not None:
        if args.features:
            print("error: Do not use --features-ini with --features", file=sys.stderr)
            sys.exit(2)

        _root_module, loaded_modules, _feature_index = _load_pyang_modules(
            TACACS_ROOT_MODULE,
            search_paths,
            local_yang_modules,
        )
        try:
            ini_disabled_features = parse_feature_ini(args.features_ini, loaded_modules)
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            sys.exit(2)

    # Run pyang.
    cmd = [
        pyang,
        "-f", args.format,
        "--tree-depth", str(args.depth),
    ]
    _append_search_path_args(cmd, search_paths)
    cmd.extend(str(module_path) for module_path in input_modules)
    if PLUGIN_DIR.exists():
        cmd.extend(["--plugindir", str(PLUGIN_DIR)])

    for feature_spec in args.features:
        cmd.extend(["--features", feature_spec])

    for feature_spec in args.exclude_features:
        cmd.extend(["--exclude-features", feature_spec])

    for module_name, disabled_features in sorted(ini_disabled_features.items()):
        cmd.extend(["--exclude-features", f"{module_name}:{','.join(disabled_features)}"])

    print(f"Running: {' '.join(cmd)}", file=sys.stderr)
    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.stderr:
        print(result.stderr, file=sys.stderr)

    if result.returncode != 0:
        print(f"pyang stopped with exit code {result.returncode}", file=sys.stderr)
        sys.exit(result.returncode)

    write_output(result.stdout, args.output)


if __name__ == "__main__":
    main()
