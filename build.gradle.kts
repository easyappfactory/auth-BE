plugins {
	kotlin("jvm") version "2.2.0"
	kotlin("plugin.spring") version "1.9.25"
	id("org.springframework.boot") version "3.5.4"
	id("io.spring.dependency-management") version "1.1.7"
	kotlin("plugin.jpa") version "2.2.0"
}

group = "com.wq"
version = "0.0.1-SNAPSHOT"

java {
	toolchain {
		languageVersion = JavaLanguageVersion.of(21)
	}
}

configurations {
	compileOnly {
		extendsFrom(configurations.annotationProcessor.get())
	}
}

repositories {
	mavenCentral()
}

extra["spring-security.version"] = "6.5.3"

dependencies {
	implementation("org.springframework.boot:spring-boot-starter-data-jpa")
	implementation("org.springframework.boot:spring-boot-starter-web")
	implementation("org.springframework.boot:spring-boot-starter-security")
	implementation("com.fasterxml.jackson.module:jackson-module-kotlin")
	implementation("org.jetbrains.kotlin:kotlin-reflect")
	implementation("org.springframework.boot:spring-boot-starter-mail")
	implementation("me.paulschwarz:spring-dotenv:4.0.0")
	runtimeOnly("com.h2database:h2")
	implementation("org.springframework.boot:spring-boot-starter-logging")
	implementation("io.github.oshai:kotlin-logging-jvm:5.1.4")
	implementation("org.springdoc:springdoc-openapi-starter-webmvc-ui:2.8.0")
	implementation("mysql:mysql-connector-java:8.0.33")

	// oauth
	implementation("com.google.api-client:google-api-client:2.7.0")
	implementation("com.google.oauth-client:google-oauth-client-jetty:1.36.0")
	implementation("com.google.apis:google-api-services-oauth2:v2-rev20200213-2.0.0")
	implementation("org.springframework.boot:spring-boot-starter-webflux")

	// test
	testImplementation("org.springframework.boot:spring-boot-starter-test")
	testImplementation("org.springframework.security:spring-security-test")
	testImplementation("org.jetbrains.kotlin:kotlin-test-junit5")
	testRuntimeOnly("org.junit.platform:junit-platform-launcher")
	testImplementation("org.mockito.kotlin:mockito-kotlin:4.1.0")

	// Kotest 버전 변수로 관리
	val kotestVersion = "5.9.1"

	testImplementation("io.kotest:kotest-runner-junit5:$kotestVersion")
	testImplementation("io.kotest:kotest-assertions-core:$kotestVersion")
	testImplementation("io.kotest:kotest-assertions-json:$kotestVersion")
	testImplementation("io.kotest:kotest-property:$kotestVersion")
	testImplementation("io.kotest.extensions:kotest-extensions-spring:1.1.3")

	testImplementation("com.fasterxml.jackson.core:jackson-databind:2.17.+")
	testImplementation("com.fasterxml.jackson.module:jackson-module-kotlin:2.17.+")
	testImplementation("com.fasterxml.jackson.datatype:jackson-datatype-jsr310:2.17.+")

	// jjwt
	implementation("io.jsonwebtoken:jjwt-api:0.12.6")
	runtimeOnly("io.jsonwebtoken:jjwt-impl:0.12.6")
	runtimeOnly("io.jsonwebtoken:jjwt-jackson:0.12.6")

	//rate limiter - token bucket
	implementation("com.bucket4j:bucket4j-core:8.7.0")
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

tasks.withType<Test> {
	useJUnitPlatform()
}
noArg {
	annotation("jakarta.persistence.Entity")
}