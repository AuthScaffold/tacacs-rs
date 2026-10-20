"""Validate explicit release policy against Cargo and emit product matrices."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

from workspace import MetadataError, inventory, load_metadata


REGISTRY_PATH = Path(".github/products.json")
MATRIX_FIELDS = (
    "os", "target", "asset_name", "package_name", "package_root",
    "artifact_name", "artifact_kind", "features", "sbom_describe",
)
POLICY_FIELDS = {*MATRIX_FIELDS, "default_features", "packaging", "sbom_formats"}

# These policies describe the existing packaging scripts, not product enrollment.
PLATFORMS = {
    ("ubuntu-latest", "x86_64-unknown-linux-gnu"): {
        "archive": "tar.gz", "debug_symbols": "split",
        "openssl_runtime": "system", "linkage": "dynamic",
    },
    ("windows-latest", "x86_64-pc-windows-msvc"): {
        "archive": "zip", "debug_symbols": "pdb",
        "openssl_runtime": "bundled-dlls", "linkage": "dynamic",
    },
}


class RegistryError(ValueError):
    """The product registry does not match Cargo or supported packaging policy."""


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise RegistryError(f"duplicate registry field: {key}")
        result[key] = value
    return result


def read_registry(path: Path) -> dict:
    """Read the registry and reject duplicate JSON fields."""
    try:
        return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_unique_object)
    except (OSError, json.JSONDecodeError) as error:
        raise RegistryError(f"cannot read product registry {path}: {error}") from error


def registry_products(data: dict, metadata: dict) -> list[dict[str, str]]:
    """Return the existing matrix shape after full schema and Cargo validation."""
    if not isinstance(data, dict) or set(data) != {"schema_version", "products"}:
        raise RegistryError("registry fields must be schema_version and products")
    if type(data["schema_version"]) is not int or data["schema_version"] != 1:
        raise RegistryError("unsupported product registry schema_version")
    if not isinstance(data["products"], list) or not data["products"]:
        raise RegistryError("registry products must be a nonempty array")

    members = {package["name"]: package for package in inventory(metadata)["packages"]}
    packages = {package["id"]: package for package in metadata["packages"]}
    assets = set()
    identities = set()
    result = []
    for product in data["products"]:
        if not isinstance(product, dict) or set(product) != POLICY_FIELDS:
            raise RegistryError("product fields must declare the complete build, packaging, and SBOM policy")
        for field in MATRIX_FIELDS:
            value = product[field]
            if not isinstance(value, str) or (field != "features" and not value):
                raise RegistryError(f"product {field} must be a string")
            if any(character in value for character in "\r\n\0"):
                raise RegistryError(f"product {field} contains a control character")
        for field in ("package_name", "artifact_name", "asset_name"):
            if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]*", product[field]):
                raise RegistryError(f"invalid product {field}: {product[field]!r}")
        platform = (product["os"], product["target"])
        if platform not in PLATFORMS:
            raise RegistryError(f"unsupported product platform: {platform}")
        if product["packaging"] != PLATFORMS[platform]:
            raise RegistryError(f"unsupported packaging policy for {platform}")
        if product["default_features"] is not True:
            raise RegistryError("product builds require default_features: true")
        if product["sbom_formats"] != ["json", "xml"]:
            raise RegistryError("product SBOM formats must be json and xml")
        kind = product["artifact_kind"]
        if kind not in ("bin", "cdylib") or (platform[0] == "windows-latest" and kind != "bin"):
            raise RegistryError(f"unsupported artifact kind for {platform}: {kind}")
        describe = "binaries" if kind == "bin" else "all-cargo-targets"
        if product["sbom_describe"] != describe:
            raise RegistryError(f"{kind} products require SBOM describe mode {describe}")
        asset = product["asset_name"]
        identity = (product["package_name"], product["artifact_name"], kind, platform)
        if asset in assets or identity in identities:
            raise RegistryError(f"duplicate product: {asset}")
        assets.add(asset)
        identities.add(identity)

        member = members.get(product["package_name"])
        if member is None:
            raise RegistryError(f"product package {product['package_name']!r} is not a workspace member")
        if product["package_root"] != member["directory"]:
            raise RegistryError(f"stale package_root for {product['package_name']}")
        package = packages[member["id"]]
        targets = [
            target for target in package.get("targets", [])
            if target["name"] == product["artifact_name"]
            and kind in target["kind"] and kind in target["crate_types"]
        ]
        if len(targets) != 1:
            raise RegistryError(f"product {asset} has no unique {kind} target named {product['artifact_name']!r}")
        features = package.get("features", {})
        requested = set(filter(None, re.split(r"[,\s]+", product["features"])))
        if requested - features.keys():
            raise RegistryError(f"unknown product features for {asset}: {sorted(requested - features.keys())}")
        enabled = requested | {"default"}
        pending = list(enabled)
        while pending:
            for feature in features.get(pending.pop(), []):
                if feature in features and feature not in enabled:
                    enabled.add(feature)
                    pending.append(feature)
        if set(targets[0].get("required-features", [])) - enabled:
            raise RegistryError(f"product {asset} does not enable its target required-features")
        result.append({field: product[field] for field in MATRIX_FIELDS})
    return result


def load_products(workspace: Path, *, target: str | None = None, linux_only: bool = False) -> list[dict[str, str]]:
    """Load the complete validated registry, then select an optional platform."""
    products = registry_products(
        read_registry(workspace / REGISTRY_PATH),
        load_metadata(workspace, target=target, no_deps=True, locked=True),
    )
    selected = [
        product for product in products
        if (target is None or product["target"] == target)
        and (not linux_only or product["os"] == "ubuntu-latest")
    ]
    if not selected:
        raise RegistryError(f"no registered products for target {target!r} (linux_only={linux_only})")
    return selected


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, default=Path("."))
    parser.add_argument("--target")
    parser.add_argument("--linux", action="store_true")
    parser.add_argument("--github-output", type=Path)
    args = parser.parse_args(argv)
    try:
        products = load_products(args.workspace.resolve(), target=args.target, linux_only=args.linux)
        output = json.dumps(products, separators=(",", ":"))
        if args.github_output is not None:
            with args.github_output.open("a", encoding="utf-8") as stream:
                stream.write(f"products={output}\n")
        print(output)
    except (RegistryError, MetadataError, OSError) as error:
        print(f"product registry error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
