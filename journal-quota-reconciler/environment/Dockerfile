FROM public.ecr.aws/docker/library/golang:1.24-bookworm@sha256:1a6d4452c65dea36aac2e2d606b01b4a029ec90cc1ae53890540ce6173ea77ac

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 GOFLAGS="-mod=mod -buildvcs=false" GOPROXY=off GOTOOLCHAIN=local

RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 python3-pip tmux asciinema \
    && rm -rf /var/lib/apt/lists/*
RUN ln -s /usr/local/go/bin/go /usr/local/bin/go && ln -s /usr/local/go/bin/gofmt /usr/local/bin/gofmt
COPY requirements.lock /tmp/requirements.lock
RUN python3 -m pip install --break-system-packages --require-hashes --no-deps -r /tmp/requirements.lock \
    && rm /tmp/requirements.lock

WORKDIR /app
COPY app/ /app/
RUN go build -o /app/bin/journal-reconcile ./cmd/journal-reconcile
