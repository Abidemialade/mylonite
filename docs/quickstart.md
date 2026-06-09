# Quickstart

## Install

Requires Python 3.11 or newer.

```bash
pip install mylonite
```

For development against the source tree:

```bash
git clone https://github.com/Abidemialade/mylonite.git
cd mylonite
python -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pre-commit install
```

## Commands that work today (v0.1.0)

```bash
mylonite version
mylonite taxonomy list --framework owasp-llm
mylonite taxonomy list --framework owasp-asi
mylonite taxonomy list --framework atlas
mylonite taxonomy list --framework nist
```

## Commands coming in v0.2

```bash
mylonite init                                            # scaffold a config
mylonite scan ./my-agent --authorize ./my-agent          # find a weakness
mylonite generate                                        # emit a regression test
mylonite validate                                        # run the test through the differential oracle
```

These stubs exist in v0.1.0 to make the surface area visible; they exit
non-zero with a "coming in v0.2" message. See
[`PLAN.md`](https://github.com/Abidemialade/mylonite/blob/main/PLAN.md) for
the implementation timeline.
