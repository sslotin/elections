# Reproducible official-verifier bug runner.
#
# The TypeScript verifier is fetched at the audited upstream revision. The
# CryptoPro CSP archive is proprietary and is downloaded during the build;
# cpblindsig.zip is kept beside this Dockerfile because it is the other native
# runtime input used by the official tool.

FROM node:16.8-bullseye

ARG OBSERVER_REPO=https://github.com/cikrf/deg2025.git
ARG OBSERVER_REF=d1fc451622342990e436afdc5849e6e9969f62c7
ARG CSP_URL=http://i.uolk.ru/st/cryptopro-csp/5.0.13000/linux-amd64_deb.tgz
ARG CSP_SHA256=d770896bd0235fd5ca85589f9c9534bf78fa0d1e97302e1f5ee2fc5fba60a342

ENV LD_LIBRARY_PATH=/opt/cprocsp/lib/amd64
ENV NODE_OPTIONS=--max_old_space_size=8192

# Install the exact CSP build used by the audited native verifier.
RUN curl -fL --retry 5 --retry-delay 2 "$CSP_URL" -o /tmp/csp.tgz \
 && echo "$CSP_SHA256  /tmp/csp.tgz" | sha256sum -c - \
 && tar -xvf /tmp/csp.tgz -C /tmp \
 && cd /tmp/linux-amd64_deb \
 && ./install.sh kc1 lsb-cprocsp-devel \
 && rm -rf /tmp/csp.tgz /tmp/linux-amd64_deb

# Fetch source rather than relying on a host checkout or a pre-existing image.
RUN git init /tmp/deg2025 \
 && cd /tmp/deg2025 \
 && git remote add origin "$OBSERVER_REPO" \
 && git fetch --depth 1 origin "$OBSERVER_REF" \
 && git checkout --detach FETCH_HEAD \
 && mkdir -p /app \
 && cp -a observer-tools/. /app/ \
 && rm -rf /tmp/deg2025

# This archive contains libcpblindsig.so. It is not published in the upstream
# Git repository, so it is supplied as a small build-context artifact.
COPY cpblindsig.zip /app/lib/cpblindsig.zip
WORKDIR /app/lib
RUN unzip -j cpblindsig.zip 'linux x64/libcpblindsig.so.*' \
 && mv libcpblindsig.so.* libcpblindsig.so \
 && gcc -fPIC -DPIC -Wall -c -g gosthash2012.c curve.c \
      -lpthread -lssl -lcrypto -lssp -lcapi10 -lcapi20 -lrdrsup \
      -L/opt/cprocsp/lib/amd64 \
      -DSIZEOF_VOID_P=8 -DHAVE_LIMITS_H -DUNIX -D_COMPACT -DHAVE_STDINT_H \
      -I/opt/cprocsp/include -I/opt/cprocsp/includes \
      -I/opt/cprocsp/include/cpcsp -I/usr/include/openssl/ \
 && gcc -shared *.o -o libgostcrypto.so -L/opt/cprocsp/lib/amd64 \
      -lcapi10 -lcapi20 -lssl -lcrypto -lssp -lrdrsup \
 && rm -f cpblindsig.zip *.o

WORKDIR /app
RUN npm ci --no-audit --no-fund && npm run build

# The image exposes the official CLI; callers pass `validate <contract-id>`.
ENTRYPOINT ["node", "/app/dist/index.js"]
