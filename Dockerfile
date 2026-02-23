FROM eclipse-temurin:21-jdk-alpine AS builder

WORKDIR /workspace

# Gradle wrapper and source
COPY gradle gradle
COPY gradlew build.gradle.kts settings.gradle.kts ./
COPY src src

RUN ./gradlew bootJar --no-daemon -x test

FROM eclipse-temurin:21-jre-alpine

RUN adduser -D -h /app appuser

WORKDIR /app

COPY --from=builder /workspace/build/libs/auth-be-0.0.1-SNAPSHOT.jar app.jar

USER appuser

EXPOSE 9000

ENTRYPOINT ["java", "-Xmx256m", "-jar", "/app/app.jar"]
