plugins {
    kotlin("jvm") version "2.3.0"
	kotlin("plugin.spring") version "2.3.0"
	kotlin("plugin.jpa") version "2.3.0"

	id("org.springframework.boot") version "4.0.4"
	id("io.spring.dependency-management") version "1.1.7"
}

group = "com.wq"
version = "0.0.1-SNAPSHOT"

java {
	toolchain {
		languageVersion = JavaLanguageVersion.of(25)
	}
}

configurations {
	compileOnly {
		extendsFrom(configurations.annotationProcessor.get())
	}
}

dependencies {
	implementation("org.springframework.boot:spring-boot-starter-data-jpa")
	implementation("org.springframework.boot:spring-boot-starter-web")
	implementation("org.springframework.boot:spring-boot-starter-security")
	implementation("org.springframework.boot:spring-boot-starter-mail")
	implementation("org.springframework.boot:spring-boot-starter-webflux")

	// 로깅 스타터 (GitHub Packages)
	implementation("com.easyapp.factory:spring-logging-starter:0.0.1-SNAPSHOT")

	// Kotlin 관련 (Kotlin 2.3 대응)
	implementation("org.jetbrains.kotlin:kotlin-reflect")
	implementation("io.github.oshai:kotlin-logging-jvm:8.0.01")

	// Database
	runtimeOnly("com.h2database:h2")
	runtimeOnly("org.postgresql:postgresql")

	// Dotenv: Spring Boot 4 전용 Artifact 사용 권장
	implementation("me.paulschwarz:springboot4-dotenv:5.1.0")

	// API Documentation (Spring Boot 4 대응을 위해 3.x 버전 사용)
	implementation("org.springdoc:springdoc-openapi-starter-webmvc-ui:3.0.2")

	// OAuth & Google API
	implementation("com.google.api-client:google-api-client:2.7.0")
	implementation("com.google.oauth-client:google-oauth-client-jetty:1.36.0")
	implementation("com.google.apis:google-api-services-oauth2:v2-rev20200213-2.0.0")

	// JWT (JJWT)
	implementation("io.jsonwebtoken:jjwt-api:0.12.6")
	runtimeOnly("io.jsonwebtoken:jjwt-impl:0.12.6")
	runtimeOnly("io.jsonwebtoken:jjwt-jackson:0.12.6")

	// Rate Limiter: Artifact 이름이 변경되었습니다
	implementation("com.bucket4j:bucket4j_jdk17-core:8.17.0")

	// HTTP Client & Utils (Spring Boot BOM이 httpclient5 버전 관리 — TlsSocketStrategy 등 포함)
	implementation("org.apache.httpcomponents.client5:httpclient5")
	implementation("com.github.f4b6a3:uuid-creator:6.1.1")

	// Testing
	val kotestVersion = "6.1.7"
	testImplementation("org.springframework.boot:spring-boot-starter-test")
	testImplementation("org.springframework.security:spring-security-test")
	testImplementation("io.kotest:kotest-runner-junit5:$kotestVersion")
	testImplementation("io.kotest:kotest-assertions-core:$kotestVersion")
	testImplementation("io.kotest:kotest-assertions-json:$kotestVersion")
	testImplementation("io.kotest:kotest-property:$kotestVersion")
	testImplementation("io.kotest.extensions:kotest-extensions-spring:1.1.3")

	// Mockito-Kotlin
	testImplementation("org.mockito.kotlin:mockito-kotlin:5.4.0")
}

kotlin {
	compilerOptions {
		freeCompilerArgs.addAll("-Xjsr305=strict")
	}
}

allOpen {
	annotation("jakarta.persistence.Entity")
	annotation("jakarta.persistence.MappedSuperclass")
	annotation("jakarta.persistence.Embeddable")
}

noArg {
	annotation("jakarta.persistence.Entity")
}

tasks.withType<Test> {
	useJUnitPlatform()
}
