# ================================
# Stage 1: Build
# ================================
FROM eclipse-temurin:25-jdk-alpine AS builder

# GITHUB_ACTOR는 빌드 시점에 일반 ARG로 넘겨받습니다.
ARG GITHUB_ACTOR=easyappfactory

WORKDIR /workspace

# Gradle wrapper and source
COPY gradle gradle
COPY gradlew build.gradle.kts settings.gradle.kts ./
COPY src src

# mount 기능을 사용하여 빌드 시점에만 GITHUB_TOKEN을 안전하게 사용합니다.
RUN --mount=type=secret,id=GITHUB_TOKEN \
    GITHUB_TOKEN=$(cat /run/secrets/GITHUB_TOKEN) \
    GITHUB_ACTOR=${GITHUB_ACTOR} \
    ./gradlew bootJar --no-daemon -x test

FROM eclipse-temurin:25-jre-alpine

RUN adduser -D -h /app appuser

WORKDIR /app

COPY --from=builder /workspace/build/libs/auth-be-0.0.1-SNAPSHOT.jar app.jar

USER appuser

EXPOSE 9000

ENTRYPOINT ["java", "-Xmx256m", "-jar", "/app/app.jar"]
