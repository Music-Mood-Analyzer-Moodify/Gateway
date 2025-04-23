FROM gradle:8.13.0-jdk21-alpine AS build
COPY --chown=gradle:gradle . /home/gradle/src
WORKDIR /home/gradle/src
RUN gradle build --no-daemon -x test --info

FROM eclipse-temurin:21-jdk-jammy

EXPOSE 8080

RUN mkdir /app

COPY --from=build /home/gradle/src/build/libs/*.jar /app/gateway.jar

ENTRYPOINT ["java", "-jar", "/app/gateway.jar"]