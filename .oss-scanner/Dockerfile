# Build image for automated security scanning of Mylonite.
#
# The scanner builds this with the repository as the build context, then removes
# network access. Everything the package, its test suite and the zero-key demo
# need is installed here, so the finished image works offline.
# .github/workflows/oss-scanner-image.yml builds it and runs the suite with
# --network none on every change to this file, the source or the dependencies.
FROM python:3.12-slim-bookworm

# LITELLM_LOCAL_MODEL_COST_MAP: Mylonite sets this itself on import; it is set
# here too so litellm never tries to fetch its model-cost map from the network.
ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_ROOT_USER_ACTION=ignore \
    LITELLM_LOCAL_MODEL_COST_MAP=True

# git: the gate and generate tests create throwaway repositories and commit to
# them, so they need an identity.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates git \
    && rm -rf /var/lib/apt/lists/* \
    && git config --system user.name "oss-scanner" \
    && git config --system user.email "oss-scanner@localhost" \
    && git config --system init.defaultBranch main

# Scanner contract: the checkout lives inside the image, at /src.
COPY . /src
WORKDIR /src

# The package with its dev tools, and the in-repo reference target the test
# suite imports (a mocked, deliberately vulnerable MCP server; see
# threat_model.md before reporting anything in it).
RUN python -m pip install -e ".[dev]" -e ./reference_targets/mcp_kitchen_sink \
    && mylonite version

# Check the image works with what the build installed, and compile bytecode:
# the zero-key demo replays a recorded vulnerable-vs-guarded run with no model
# and no API key, and the suite runs fully offline. A failing test is reported,
# not fatal, so a flaky test never blocks the scan.
RUN (cd /tmp && mylonite demo || echo "WARNING: mylonite demo failed") \
    && (python -m pytest -n auto -q -p no:cacheprovider \
        || echo "WARNING: pytest reported failures")
