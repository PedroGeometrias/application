#!/bin/sh
set -eu

mkdir -p /data/signing

if [ "${REPORT_SIGNING_ENABLED:-true}" = "true" ] \
    && { [ ! -f /data/signing/private.pem ] || [ ! -f /data/signing/public.pem ]; }; then
    umask 077
    threatcore keygen /data/signing/private.pem /data/signing/public.pem
fi

exec java ${JAVA_OPTS:-} -jar /app/threatlens.jar
