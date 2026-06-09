# JSON Schemas

This directory contains JSON Schemas generated from the Pydantic models in
`mylonite.contracts._types`. They are the **wire format** that plugin
manifests, community-registry pattern files, and config files validate
against — they exist so tooling outside Python (or outside Mylonite
entirely) does not need a runtime dependency on this package.

## Regenerating

After any change to `mylonite.contracts._types`, regenerate:

```bash
python scripts/regenerate_schemas.py
```

The script is idempotent. CI checks that a clean checkout produces no diff
after running it; if you see a CI failure here, you forgot to regenerate.
