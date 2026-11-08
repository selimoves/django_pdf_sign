# Образ с КриптоПро CSP и pycades для интероп-проверки.
#
# Архив CSP нельзя распространять: положите linux-amd64_deb.tgz в
# docker/cryptopro/dist/ (скачивается с cryptopro.ru после входа).
ARG PYTHON_VER=3.12
FROM python:${PYTHON_VER}

ENV DEBIAN_FRONTEND=noninteractive
ENV PATH="/opt/cprocsp/bin/amd64:/opt/cprocsp/sbin/amd64:${PATH}"

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        git cmake build-essential libboost-all-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY dist/ /tmp/dist/
RUN test -f /tmp/dist/linux-amd64_deb.tgz \
    && mkdir /tmp/csp \
    && tar -xzf /tmp/dist/linux-amd64_deb.tgz -C /tmp/csp --strip-components=1 \
    && cd /tmp/csp \
    && chmod +x install*.sh \
    && ./install.sh kc1 lsb-cprocsp-devel cprocsp-legacy cprocsp-pki-cades \
    && rm -rf /tmp/csp /tmp/dist

RUN git clone --depth 1 https://github.com/CryptoPro/pycades.git /opt/pycades \
    && pip install --no-cache-dir /opt/pycades

RUN certmgr -install -pfx -file /opt/pycades/tests/fixtures/pycades-test.pfx -newpin "" \
    && (echo o | certmgr -install -file /opt/pycades/tests/fixtures/pycades-root.cer -store uRoot) \
    && (echo o | certmgr -install -crl -file /opt/pycades/tests/fixtures/pycades-root.crl -store uCA) \
    && certmgr -list -store uMy | grep -q pycades-test \
    && certmgr -list -crl -store uCA | grep -q pycades-root

COPY sign.py /opt/sign.py
ENTRYPOINT ["python", "/opt/sign.py"]
