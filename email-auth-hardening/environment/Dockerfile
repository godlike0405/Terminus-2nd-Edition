FROM public.ecr.aws/docker/library/node:22-bookworm-slim@sha256:f3a68cf41a855d227d1b0ab832bed9749469ef38cf4f58182fb8c893bc462383

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    NPM_CONFIG_FUND=false \
    NPM_CONFIG_AUDIT=false

RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 python3-pip tmux asciinema \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Verifier tooling (pytest, pytest-json-ctrf) lives in a stable cache layer.
COPY requirements.lock /tmp/requirements.lock
RUN python3 -m pip install --break-system-packages --require-hashes --no-deps -r /tmp/requirements.lock \
    && rm /tmp/requirements.lock

# Node dependencies (the TypeScript compiler and its type stubs) install from the
# lockfile before any source is copied so edits stay in the top layers.
COPY package.json package-lock.json tsconfig.json ./
RUN npm ci

COPY app/ /app/

# Compile the tool once so it is runnable exactly as shipped.
RUN npm run build

RUN chmod +x /app/bin/mailguard
