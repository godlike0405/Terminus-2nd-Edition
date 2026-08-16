FROM public.ecr.aws/docker/library/node:22-bookworm-slim@sha256:f3a68cf41a855d227d1b0ab832bed9749469ef38cf4f58182fb8c893bc462383 AS builder
WORKDIR /src
COPY package.json package-lock.json tsconfig.json ./
COPY app/src/ ./app/src/
RUN npm ci \
    && npm run build

FROM public.ecr.aws/docker/library/node:22-bookworm-slim@sha256:f3a68cf41a855d227d1b0ab832bed9749469ef38cf4f58182fb8c893bc462383
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN apt-get update \
    && apt-get install -y --no-install-recommends asciinema cryptsetup-bin logrotate python3 python3-pip systemd tmux udev \
    && rm -rf /var/lib/apt/lists/*
COPY requirements.lock /tmp/requirements.lock
RUN python3 -m pip install --break-system-packages --require-hashes --no-deps -r /tmp/requirements.lock \
    && rm /tmp/requirements.lock
WORKDIR /app
COPY app/ /app/
COPY --from=builder /src/app/dist/ /app/dist/
RUN mkdir -p /usr/local/libexec /etc/systemd/system /etc/sysusers.d /etc/tmpfiles.d /etc/udev/rules.d /etc/logrotate.d \
    && install -m 0755 /app/archive-cartridge-worker /usr/local/libexec/archive-cartridge-worker \
    && chmod +x /app/bin/cartridge-inventory /app/bin/cartridge-policy-check \
    && printf '%s\n' \
       'SUBSYSTEM=="block", ENV{ID_FS_TYPE}=="crypto_LUKS", TAG+="systemd", ENV{SYSTEMD_WANTS}+="archive-cartridge@%E{ID_FS_UUID}.service"' \
       > /etc/udev/rules.d/70-archive-cartridge.rules \
    && printf '%s\n' '[Unit]' 'Description=Legacy cartridge backup' '[Service]' 'ExecStart=/bin/true' \
       > /etc/systemd/system/archive-cartridge.service
