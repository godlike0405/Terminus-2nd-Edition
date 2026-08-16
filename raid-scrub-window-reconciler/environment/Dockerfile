FROM public.ecr.aws/docker/library/node:22-bookworm-slim@sha256:f3a68cf41a855d227d1b0ab832bed9749469ef38cf4f58182fb8c893bc462383

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    NPM_CONFIG_AUDIT=false \
    NPM_CONFIG_FUND=false

RUN apt-get update \
    && apt-get install -y --no-install-recommends asciinema python3 python3-pip tmux \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.lock /tmp/requirements.lock
RUN python3 -m pip install --break-system-packages --require-hashes --no-deps -r /tmp/requirements.lock \
    && rm /tmp/requirements.lock

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY app/ /app/
RUN npm run check && chmod +x /app/bin/scrub-window
