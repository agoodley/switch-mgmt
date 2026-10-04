# syntax=docker/dockerfile:1.7
#
# Toolbox: Ansible + cisco.ios collection + netaudit (STP analyser, CDP
# discovery and the lab simulator).  Built by `make build`.

FROM python:3.12-slim-trixie

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    ANSIBLE_FORCE_COLOR=1 \
    ANSIBLE_COLLECTIONS_PATH=/usr/share/ansible/collections \
    HOME=/home/netops

RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-client git make curl iputils-ping less ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Optional extra CA certificate for networks with a TLS-inspecting proxy:
#   EXTRA_CA_CERT=/path/to/ca.crt make build
# The path is passed as a build argument only so that changing it rebuilds
# this layer (secret contents are not part of the build cache key).
ARG EXTRA_CA_CERT=
RUN --mount=type=secret,id=extra_ca,required=false \
    if [ -s /run/secrets/extra_ca ]; then \
      cp /run/secrets/extra_ca /usr/local/share/ca-certificates/extra-ca.crt && update-ca-certificates; \
    fi

COPY ansible/requirements.txt /tmp/requirements.txt
RUN pip install -r /tmp/requirements.txt

COPY ansible/requirements.yml /tmp/requirements.yml
RUN ansible-galaxy collection install -r /tmp/requirements.yml -p /usr/share/ansible/collections \
 && rm -rf /root/.ansible

COPY netaudit /opt/netaudit
RUN pip install "/opt/netaudit[lab,discover]" pytest

# Works whatever uid the container runs as (compose passes the host user's
# PUID/PGID so files in reports/ and backups/ belong to you).
RUN groupadd -g 1000 netops && useradd -u 1000 -g 1000 -d /home/netops -m -s /bin/bash netops \
 && mkdir -p /home/netops/.ansible /home/netops/.ssh \
 && chmod -R a+rwX /home/netops

COPY docker/toolbox/entrypoint.sh /usr/local/bin/toolbox-entrypoint

WORKDIR /work/ansible
ENTRYPOINT ["toolbox-entrypoint"]
CMD ["bash"]
