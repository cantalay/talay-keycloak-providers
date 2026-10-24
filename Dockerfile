# Talay Keycloak eklentileri: init container olarak JAR'ı Keycloak'ın providers birimine kopyalar (talay-identity, keycloakx
# extraInitContainers). JAR CI'da `./mvnw verify` ile target/ altında üretilir.
FROM busybox:1.37.0-musl@sha256:5cec3fc171c87218698e85a52af7087de727372aae264a787b8112901a5b0092
COPY target/talay-keycloak-providers.jar /providers/talay-keycloak-providers.jar
USER 65534:65534
ENTRYPOINT ["cp", "-f", "/providers/talay-keycloak-providers.jar", "/target/"]
