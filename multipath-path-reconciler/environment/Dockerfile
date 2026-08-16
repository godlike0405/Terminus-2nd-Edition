FROM public.ecr.aws/docker/library/debian:bookworm-slim@sha256:4724b8cc51e33e398f0e2e15e18d5ec2851ff0c2280647e1310bc1642182655d

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends asciinema initramfs-tools lvm2 multipath-tools python3 python3-pip systemd tmux udev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.lock /tmp/requirements.lock
RUN python3 -m pip install --break-system-packages --require-hashes --no-deps -r /tmp/requirements.lock \
    && rm /tmp/requirements.lock

COPY app/data/ /opt/san-host/
COPY app/docs/remediation.md /opt/san-host/remediation.md
COPY app/baseline/multipath.conf /etc/multipath.conf
COPY app/baseline/wwids /etc/multipath/wwids
COPY app/baseline/90-legacy-san.conf /etc/multipath/conf.d/90-legacy-san.conf
COPY app/baseline/90-legacy-timeouts.rules /etc/udev/rules.d/90-legacy-timeouts.rules
COPY app/baseline/legacy-multipath.conf /etc/systemd/system/multipathd.service.d/legacy-multipath.conf
COPY app/baseline/db-ledger.mount /etc/systemd/system/db-ledger.mount
COPY app/baseline/queue-archive.mount /etc/systemd/system/queue-archive.mount
COPY app/baseline/audit-vault.mount /etc/systemd/system/audit-vault.mount
COPY app/baseline/lvm.conf /etc/lvm/lvm.conf
COPY app/baseline/initramfs-modules /etc/initramfs-tools/modules
COPY app/baseline/legacy-root.conf /etc/initramfs-tools/conf.d/legacy-root.conf

WORKDIR /root
