# Talay Keycloak eklentileri: init container olarak JAR'ları Keycloak'ın providers birimine kopyalar (talay-identity, keycloakx
# extraInitContainers). talay-keycloak-providers.jar CI'da `./mvnw verify` ile, apple-identity-provider.jar (Apple ile giriş,
# klausbetz/apple-identity-provider-keycloak) aynı derlemede sürüm sayfasından sağlaması doğrulanarak target/ altına iner.
FROM busybox:1.37.0-musl@sha256:5cec3fc171c87218698e85a52af7087de727372aae264a787b8112901a5b0092
COPY target/talay-keycloak-providers.jar target/apple-identity-provider.jar /providers/
USER 65534:65534
ENTRYPOINT ["sh", "-c", "cp -f /providers/*.jar /target/"]
