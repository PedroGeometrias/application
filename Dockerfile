FROM eclipse-temurin:17-jdk-jammy AS native-build
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential libssl-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src/native
COPY native/ ./
RUN make clean test && make clean all

FROM maven:3.9.9-eclipse-temurin-17 AS java-build
WORKDIR /src/backend
COPY backend/pom.xml ./
RUN mvn -B -q dependency:go-offline
COPY backend/src ./src
RUN mvn -B -q verify

FROM eclipse-temurin:17-jre-jammy
RUN apt-get update \
    && apt-get install -y --no-install-recommends libssl3 curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --create-home threatlens
WORKDIR /app
COPY --from=native-build /src/native/build/threatcore /usr/local/bin/threatcore
COPY --from=java-build /src/backend/target/threatlens-1.0.0.jar /app/threatlens.jar
COPY scripts/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod 0755 /usr/local/bin/threatcore /usr/local/bin/docker-entrypoint.sh \
    && mkdir -p /data/signing \
    && chown -R threatlens:threatlens /data /app

USER threatlens
ENV THREATCORE_PATH=/usr/local/bin/threatcore \
    THREATCORE_REQUIRED=true \
    THREATLENS_DB_PATH=/data/threatlens.db \
    REPORT_PRIVATE_KEY_PATH=/data/signing/private.pem \
    REPORT_PUBLIC_KEY_PATH=/data/signing/public.pem
EXPOSE 8080
VOLUME ["/data"]
HEALTHCHECK --interval=20s --timeout=4s --start-period=25s --retries=3 \
    CMD curl --fail --silent http://localhost:8080/actuator/health || exit 1
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
