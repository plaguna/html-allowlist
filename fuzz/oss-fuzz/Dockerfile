# OSS-Fuzz build container for html-allowlist.
# Lives at projects/html-allowlist/Dockerfile in google/oss-fuzz once accepted.
FROM gcr.io/oss-fuzz-base/base-builder-javascript

# html-allowlist requires Node >= 22.12 (see package.json engines); upgrade if
# the base image ships something older.
RUN node --version | grep -qE "v(2[2-9]|[3-9][0-9])" || \
    (curl -fsSL https://deb.nodesource.com/setup_22.x | bash - && \
     apt-get install -y nodejs)

RUN git clone --depth 1 https://github.com/plaguna/html-allowlist html-allowlist
WORKDIR $SRC/html-allowlist
COPY build.sh $SRC/
