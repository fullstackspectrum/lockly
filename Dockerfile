# syntax=docker/dockerfile:1

# Docker Hardened Images (https://dhi.io), Alpine variant: a minimal, non-root Python
# runtime with no shell or package manager. Pulling them needs `docker login dhi.io`
# with a Docker account. With no git in the image, it compares two lockfile files;
# use pip, Homebrew or the GitHub Action for --base (git) mode.
ARG PYTHON_VERSION=3.14

FROM dhi.io/python:${PYTHON_VERSION}-alpine-dev AS build
WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY lockly ./lockly
# The venv is created without pip so the runtime image ships only Lockly (which has
# no runtime dependencies); the build stage's pip installs into it from outside.
RUN python3 -m venv --without-pip /opt/venv \
    && pip --python /opt/venv/bin/python install --no-cache-dir . \
    && mkdir /data

FROM dhi.io/python:${PYTHON_VERSION}-alpine
ARG VERSION=dev
LABEL org.opencontainers.image.title="lockly" \
      org.opencontainers.image.description="Explain lockfile changes and flag the ones that deserve a review" \
      org.opencontainers.image.source="https://github.com/fullstackspectrum/lockly" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${VERSION}"

# The lookup cache goes to /tmp, which the non-root user can always write.
ENV PATH=/opt/venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    LOCKLY_CACHE_DIR=/tmp/lockly

COPY --from=build /opt/venv /opt/venv
# The runtime image has no shell, so /data is created in the build stage.
COPY --from=build --chown=65532:65532 /data /data

USER 65532:65532
# Mount the directory holding the lockfiles here.
WORKDIR /data
ENTRYPOINT ["lockly"]
CMD ["--help"]
