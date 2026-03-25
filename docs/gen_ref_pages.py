"""Generate API reference pages dynamically via mkdocs-gen-files.

This script is run by mkdocs-gen-files during ``mkdocs build``.
It walks the ``lacme`` package and generates a markdown file for each
public module, using mkdocstrings directives to auto-document from
docstrings.
"""

from pathlib import Path

import mkdocs_gen_files

nav = mkdocs_gen_files.Nav()

SRC = Path("lacme")

# Modules to document (in nav order)
MODULES = [
    ("Client", "client"),
    ("Certificate Authority", "ca"),
    ("ACME Responder", "acme_server"),
    ("Store", "store"),
    ("Challenges", "challenges/__init__"),
    ("HTTP-01 Handler", "challenges/http01"),
    ("DNS-01 Handler", "challenges/dns01"),
    ("DNS Providers", None),  # section header
    ("Cloudflare", "challenges/providers/cloudflare"),
    ("Route53", "challenges/providers/route53"),
    ("Hook", "challenges/providers/hook"),
    ("Crypto", "crypto"),
    ("Events", "events"),
    ("mTLS Helpers", "mtls"),
    ("Rate Limiting", "ratelimit"),
    ("Models", "models"),
    ("Errors", "errors"),
    ("Sync Client", "sync"),
    ("Testing", "testing"),
    ("CLI", "cli"),
    ("Metrics", "metrics"),
    ("ASGI Middleware", "asgi"),
    ("Uvicorn Helpers", "uvicorn"),
    ("Starlette Integration", "starlette"),
    ("FastAPI Integration", "ext_fastapi"),
    ("Types", "_types"),
]

for title, module_path in MODULES:
    if module_path is None:
        continue

    # Convert path to Python module name
    parts = module_path.replace("/", ".").split(".")
    if parts[-1] == "__init__":
        module_name = "lacme." + ".".join(parts[:-1])
        doc_path = "/".join(parts[:-1]) + "/index.md"
    else:
        module_name = "lacme." + ".".join(parts)
        doc_path = "/".join(parts) + ".md"

    full_doc_path = Path("api", doc_path)

    with mkdocs_gen_files.open(full_doc_path, "w") as fd:
        fd.write(f"# {title}\n\n")
        fd.write(f"::: {module_name}\n")

    mkdocs_gen_files.set_edit_path(full_doc_path, Path("..") / SRC / (module_path + ".py"))

    nav_parts = [title]
    nav[nav_parts] = doc_path  # relative to api/ where SUMMARY.md lives

with mkdocs_gen_files.open("api/SUMMARY.md", "w") as nav_file:
    nav_file.writelines(nav.build_literate_nav())
