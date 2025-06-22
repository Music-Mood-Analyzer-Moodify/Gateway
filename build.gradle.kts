plugins {
	java
	id("org.springframework.boot") version "3.4.4"
	id("io.spring.dependency-management") version "1.1.7"
}

group = "com.moodify"
version = "0.0.1-SNAPSHOT"

java {
	toolchain {
		languageVersion = JavaLanguageVersion.of(21)
	}
}

repositories {
	mavenCentral()
}

extra["springCloudVersion"] = "2024.0.1"

dependencies {
	annotationProcessor("org.projectlombok:lombok:1.18.36")
	compileOnly("org.projectlombok:lombok:1.18.36")
	implementation("io.micrometer:micrometer-registry-otlp:1.15.0-M3")
	implementation("io.opentelemetry.instrumentation:opentelemetry-spring-boot-starter:2.12.0")
	implementation("org.springframework.cloud:spring-cloud-starter-gateway")
    implementation("com.google.firebase:firebase-admin:9.4.3")
	implementation("io.grpc:grpc-netty:1.71.0")
	testImplementation("org.springframework.boot:spring-boot-starter-test")
	testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

dependencyManagement {
	imports {
		mavenBom("org.springframework.cloud:spring-cloud-dependencies:${property("springCloudVersion")}")
	}
}

tasks.withType<Test> {
	useJUnitPlatform()
}
