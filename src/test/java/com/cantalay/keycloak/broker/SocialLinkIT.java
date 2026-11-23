package com.cantalay.keycloak.broker;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.MountableFile;

import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Gerçek Keycloak'ta (eklenti JAR'ı yüklü) sosyal ilk giriş ve giriş sonrası denetim. {@code fakegoogle} realm'i Google'ın
 * yerini tutar: {@code app} realm'i onu OIDC kimlik sağlayıcısı olarak aracılar; ilk giriş akışı talay-identity
 * {@code social-first-login} ({@code idp-create-user-if-unique} + {@code idp-auto-link-verified-only}, ikisi ALTERNATIVE),
 * giriş sonrası akışı {@code social-post-login} ({@code idp-unverified-account-guard}). Tarayıcı kısmı
 * ({@code kc_idp_hint} → sahte Google formu → uygulamanın dönüş adresi) HTTP istemcisiyle sürülür.
 */
@Testcontainers(disabledWithoutDocker = true)
class SocialLinkIT {

    private static final String KEYCLOAK_IMAGE = System.getProperty("it.keycloak.image", "quay.io/keycloak/keycloak:26.7.3");
    private static final String PASSWORD = "Ilk-Parola-2026!";
    private static final String GOOGLE_PASSWORD = "google-password";
    private static final String REDIRECT = "app://auth";
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final HttpClient HTTP = HttpClient.newHttpClient();

    @Container
    @SuppressWarnings("resource")
    static final GenericContainer<?> KEYCLOAK = new GenericContainer<>(KEYCLOAK_IMAGE)
            .withCommand("start-dev")
            .withEnv("KC_BOOTSTRAP_ADMIN_USERNAME", "admin")
            .withEnv("KC_BOOTSTRAP_ADMIN_PASSWORD", "admin")
            .withCopyFileToContainer(MountableFile.forHostPath(providersJar()), "/opt/keycloak/providers/talay-keycloak-providers.jar")
            .withExposedPorts(8080)
            .waitingFor(Wait.forHttp("/realms/master/.well-known/openid-configuration").forPort(8080)
                    .withStartupTimeout(Duration.ofMinutes(5)));

    @BeforeAll
    static void configure() throws Exception {
        // Google'ın yerine geçen realm: e-posta + email_verified kimlik belirtecinde (varsayılan "email" kapsamı)
        adminPost("/admin/realms", Map.of("realm", "fakegoogle", "enabled", true));
        adminPost("/admin/realms/fakegoogle/clients", Map.of("clientId", "app-broker", "secret", "it-broker-secret",
                "publicClient", false, "standardFlowEnabled", true, "redirectUris", List.of("*")));
        // Büyük/küçük harfli e-posta: Keycloak e-postayı küçük harfle saklar, bu istemci e-postayı sabit iddiayla verir
        adminPost("/admin/realms/fakegoogle/clients", Map.of("clientId", "case-broker", "secret", "it-broker-secret",
                "publicClient", false, "standardFlowEnabled", true, "redirectUris", List.of("*"),
                "defaultClientScopes", List.of("basic", "profile"),
                "protocolMappers", List.of(hardcoded("email", "placeholder@ornek.test", "String"),
                        hardcoded("email_verified", "true", "boolean"))));
        // E-posta vermeyen sağlayıcı (Apple'ın sonraki girişleri gibi): e-posta kapsamı yok
        adminPost("/admin/realms/fakegoogle/clients", Map.of("clientId", "noemail-broker", "secret", "it-broker-secret",
                "publicClient", false, "standardFlowEnabled", true, "redirectUris", List.of("*"),
                "defaultClientScopes", List.of("basic", "profile")));

        adminPost("/admin/realms", Map.of("realm", "app", "enabled", true, "registrationAllowed", true));
        adminPost("/admin/realms/app/clients", Map.of("clientId", "app-gateway", "publicClient", true,
                "standardFlowEnabled", true, "directAccessGrantsEnabled", true, "redirectUris", List.of(REDIRECT)));
        flow("social-first-login", List.of("idp-create-user-if-unique", "idp-auto-link-verified-only"), "ALTERNATIVE");
        flow("social-post-login", List.of("idp-unverified-account-guard"), "REQUIRED");
        provider("google", "app-broker", true, "openid email profile");
        provider("untrusted", "app-broker", false, "openid email profile");
        provider("google-case", "case-broker", true, "openid profile");
        provider("noemail", "noemail-broker", true, "openid profile");
    }

    /* ======================= ilk giriş ======================= */

    @Test
    void linksAnAccountWhoseEmailIsVerified() throws Exception {
        String email = newEmail();
        String id = createUser("app", email, email, true, PASSWORD);
        String googleId = createUser("fakegoogle", email, email, true, GOOGLE_PASSWORD);

        Broker result = signIn("google", email);
        assertThat(result.error()).isNull();
        assertThat(subjectOf(exchange(result.code()))).isEqualTo(id);
        List<JsonNode> links = adminGetArray("/admin/realms/app/users/" + id + "/federated-identity");
        assertThat(links).hasSize(1);
        assertThat(links.get(0).get("identityProvider").asText()).isEqualTo("google");
        assertThat(links.get(0).get("userId").asText()).isEqualTo(googleId);
        assertThat(usersWithEmail(email)).hasSize(1);
    }

    @Test
    void refusesAnAccountWhoseEmailIsNotVerifiedWithoutLinkingOrSession() throws Exception {
        String email = newEmail();
        String id = createUser("app", email, email, false, PASSWORD);
        createUser("fakegoogle", email, email, true, GOOGLE_PASSWORD);

        Broker refused = signIn("google", email);
        assertThat(refused.code()).isNull();
        assertThat(refused.error()).isEqualTo("access_denied");
        assertThat(refused.description()).isEqualTo("account_exists_unverified");
        assertThat(refused.state()).isEqualTo(refused.sentState());
        assertThat(refused.ssoCookie()).as("SSO çerezi yazılmamalı").isFalse();
        assertThat(adminGetArray("/admin/realms/app/users/" + id + "/federated-identity")).isEmpty();
        assertThat(adminGetArray("/admin/realms/app/users/" + id + "/sessions")).isEmpty();
        assertThat(usersWithEmail(email)).hasSize(1);
        assertThat(adminGet("/admin/realms/app/users/" + id).get("emailVerified").asBoolean()).isFalse();

        // ikinci deneme de aynı (kalıntı yok)
        assertThat(signIn("google", email).description()).isEqualTo("account_exists_unverified");

        // adres sahibi onaylayınca (ör. parola sıfırlama) aynı hesaba bağlanır
        adminPut("/admin/realms/app/users/" + id, Map.of("emailVerified", true));
        Broker linked = signIn("google", email);
        assertThat(linked.error()).isNull();
        assertThat(subjectOf(exchange(linked.code()))).isEqualTo(id);
    }

    @Test
    void createsANewUserWhenNoAccountHasTheEmail() throws Exception {
        String email = newEmail();
        String googleId = createUser("fakegoogle", email, email, true, GOOGLE_PASSWORD);

        Broker result = signIn("google", email);
        assertThat(result.error()).isNull();
        List<JsonNode> users = usersWithEmail(email);
        assertThat(users).hasSize(1);
        String id = users.get(0).get("id").asText();
        assertThat(subjectOf(exchange(result.code()))).isEqualTo(id);
        assertThat(users.get(0).get("emailVerified").asBoolean()).isTrue(); // trustEmail + email_verified
        assertThat(adminGetArray("/admin/realms/app/users/" + id + "/credentials")).isEmpty();
        assertThat(adminGetArray("/admin/realms/app/users/" + id + "/federated-identity").get(0).get("userId").asText())
                .isEqualTo(googleId);
    }

    /** Apple ikinci girişten sonra e-posta vermez; ilk girişi e-postasız gelen sağlayıcı yeni kullanıcı açar. */
    @Test
    void providerWithoutEmailCreatesANewUser() throws Exception {
        String username = "noemail-" + UUID.randomUUID().toString().substring(0, 8);
        String googleId = createUser("fakegoogle", username, newEmail(), true, GOOGLE_PASSWORD);

        Broker result = signIn("noemail", username, true);
        assertThat(result.error()).as("e-postasız giriş reddedilmemeli").isNull();
        List<JsonNode> users = adminGetArray("/admin/realms/app/users?exact=true&username=" + enc(username));
        assertThat(users).hasSize(1);
        String id = users.get(0).get("id").asText();
        assertThat(adminGetArray("/admin/realms/app/users/" + id + "/federated-identity").get(0).get("userId").asText())
                .isEqualTo(googleId);
    }

    @Test
    void emailCaseDoesNotMatter() throws Exception {
        String local = newEmail();
        String mixed = local.substring(0, 1).toUpperCase() + local.substring(1, local.indexOf('@')) + "@ORNEK.Test";
        hardcodedEmail(mixed);

        String verified = createUser("app", local, local, true, PASSWORD);
        createUser("fakegoogle", "case-" + local, "case-" + local, true, GOOGLE_PASSWORD);
        Broker linked = signIn("google-case", "case-" + local);
        assertThat(linked.error()).isNull();
        assertThat(subjectOf(exchange(linked.code()))).isEqualTo(verified);

        String otherLocal = newEmail();
        String otherMixed = otherLocal.toUpperCase().replace("@ORNEK.TEST", "@Ornek.TEST");
        hardcodedEmail(otherMixed);
        String unverified = createUser("app", otherLocal, otherLocal, false, PASSWORD);
        createUser("fakegoogle", "case-" + otherLocal, "case-" + otherLocal, true, GOOGLE_PASSWORD);
        Broker refused = signIn("google-case", "case-" + otherLocal);
        assertThat(refused.description()).isEqualTo("account_exists_unverified");
        assertThat(adminGetArray("/admin/realms/app/users/" + unverified + "/federated-identity")).isEmpty();
        assertThat(usersWithEmail(otherLocal)).hasSize(1);
    }

    @Test
    void providerThatDoesNotVouchForTheEmailIsNotLinked() throws Exception {
        // sağlayıcı email_verified=false diyor
        String email = newEmail();
        String id = createUser("app", email, email, true, PASSWORD);
        createUser("fakegoogle", email, email, false, GOOGLE_PASSWORD);
        Broker unverifiedAtProvider = signIn("google", email);
        assertThat(unverifiedAtProvider.error()).isEqualTo("access_denied");
        assertThat(unverifiedAtProvider.description()).isEqualTo("account_exists");
        assertThat(adminGetArray("/admin/realms/app/users/" + id + "/federated-identity")).isEmpty();

        // kimlik sağlayıcıda trustEmail kapalı
        String other = newEmail();
        String otherId = createUser("app", other, other, true, PASSWORD);
        createUser("fakegoogle", other, other, true, GOOGLE_PASSWORD);
        assertThat(signIn("untrusted", other).description()).isEqualTo("account_exists");
        assertThat(adminGetArray("/admin/realms/app/users/" + otherId + "/federated-identity")).isEmpty();
        assertThat(usersWithEmail(other)).hasSize(1);
    }

    @Test
    void sameUsernameWithAnotherEmailIsNotLinked() throws Exception {
        String username = "ayni-" + UUID.randomUUID().toString().substring(0, 8);
        String id = createUser("app", username, newEmail(), true, PASSWORD);
        String googleEmail = newEmail();
        createUser("fakegoogle", username, googleEmail, true, GOOGLE_PASSWORD);

        Broker refused = signIn("google", username);
        assertThat(refused.description()).isEqualTo("account_exists");
        assertThat(adminGetArray("/admin/realms/app/users/" + id + "/federated-identity")).isEmpty();
        assertThat(usersWithEmail(googleEmail)).isEmpty();
    }

    /* ======================= giriş sonrası denetim (eski bağlar) ======================= */

    @Test
    void existingLinkToAnUnverifiedPasswordAccountDoesNotSignIn() throws Exception {
        String email = newEmail();
        String id = createUser("app", email, email, false, PASSWORD);
        String googleId = createUser("fakegoogle", email, email, true, GOOGLE_PASSWORD);
        link(id, "google", googleId, email); // eski idp-auto-link döneminden kalan bağ

        Broker refused = signIn("google", email);
        assertThat(refused.error()).isEqualTo("access_denied");
        assertThat(refused.description()).isEqualTo("account_exists_unverified");
        assertThat(refused.ssoCookie()).isFalse();
        assertThat(adminGetArray("/admin/realms/app/users/" + id + "/sessions")).isEmpty();
        assertThat(adminGetArray("/admin/realms/app/users/" + id + "/federated-identity")).hasSize(1); // bağa dokunulmaz
        // parolayla giriş açık kalır
        assertThat(passwordGrant(email, PASSWORD).statusCode()).isEqualTo(200);
    }

    @Test
    void existingLinksOfVerifiedOrPasswordlessAccountsSignIn() throws Exception {
        String verifiedEmail = newEmail();
        String verified = createUser("app", verifiedEmail, verifiedEmail, true, PASSWORD);
        link(verified, "google", createUser("fakegoogle", verifiedEmail, verifiedEmail, true, GOOGLE_PASSWORD), verifiedEmail);
        assertThat(subjectOf(exchange(signIn("google", verifiedEmail).code()))).isEqualTo(verified);

        String passwordlessEmail = newEmail();
        String passwordless = createUser("app", passwordlessEmail, passwordlessEmail, false, null);
        link(passwordless, "google", createUser("fakegoogle", passwordlessEmail, passwordlessEmail, true, GOOGLE_PASSWORD),
                passwordlessEmail);
        assertThat(subjectOf(exchange(signIn("google", passwordlessEmail).code()))).isEqualTo(passwordless);
    }

    /* ======================= tarayıcı ======================= */

    /** Akışın bittiği yer: uygulamanın dönüş adresindeki {@code code} ya da {@code error}. */
    record Broker(String code, String error, String description, String state, String sentState, boolean ssoCookie) {
    }

    /** Taze bir "tarayıcıyla" (kendi çerezleri) {@code kc_idp_hint} ile girer, sahte Google formunu doldurur. */
    private static Broker signIn(String alias, String googleUsername) throws Exception {
        return signIn(alias, googleUsername, false);
    }

    /**
     * @param profilePageEnds e-postasız yeni kullanıcıda app realm'inin kendi profil tamamlama sayfası (bildirimsel kullanıcı
     *                        profili e-posta ister) akışın sonu sayılır; o noktada kullanıcı açılmış ve bağlanmıştır
     */
    private static Broker signIn(String alias, String googleUsername, boolean profilePageEnds) throws Exception {
        CookieJar cookies = new CookieJar();
        String state = UUID.randomUUID().toString();
        URI next = URI.create(keycloakUrl() + "/realms/app/protocol/openid-connect/auth?client_id=app-gateway&response_type=code"
                + "&scope=" + enc("openid email profile") + "&redirect_uri=" + enc(REDIRECT) + "&kc_idp_hint=" + alias
                + "&state=" + state + "&nonce=" + UUID.randomUUID());
        HttpRequest request = HttpRequest.newBuilder(next).GET().build();
        for (int hop = 0; hop < 25; hop++) {
            HttpResponse<String> response = HTTP.send(cookies.attach(request, next), HttpResponse.BodyHandlers.ofString());
            cookies.store(next, response);
            int status = response.statusCode();
            if (status >= 300 && status < 400) {
                String location = response.headers().firstValue("Location").orElseThrow();
                if (location.startsWith(REDIRECT)) {
                    Map<String, String> q = query(URI.create(location).getRawQuery());
                    return new Broker(q.get("code"), q.get("error"), q.get("error_description"), q.get("state"), state,
                            cookies.has("KEYCLOAK_IDENTITY", "/realms/app/"));
                }
                next = next.resolve(location);
                request = HttpRequest.newBuilder(next).GET().build();
                continue;
            }
            Matcher form = Pattern.compile("<form[^>]*id=\"kc-form-login\"[^>]*action=\"([^\"]+)\"").matcher(response.body());
            if (status == 200 && form.find()) {
                next = URI.create(form.group(1).replace("&amp;", "&"));
                request = HttpRequest.newBuilder(next)
                        .header("Content-Type", "application/x-www-form-urlencoded")
                        .POST(HttpRequest.BodyPublishers.ofString(formBody(Map.of("username", googleUsername,
                                "password", GOOGLE_PASSWORD, "credentialId", ""))))
                        .build();
                continue;
            }
 if (profilePageEnds && status == 200 && next.getPath().startsWith("/realms/app/") && response.body().contains("kc-update-profile-form")) {
                return new Broker(null, null, null, null, state, cookies.has("KEYCLOAK_IDENTITY", "/realms/app/"));
            }
            Matcher title = Pattern.compile("<title>([^<]*)</title>").matcher(response.body());
            throw new AssertionError("Giriş " + next.getPath() + " sayfasında durdu, HTTP " + status + ": "
                    + (title.find() ? title.group(1) : response.body().substring(0, Math.min(300, response.body().length()))));
        }
        throw new AssertionError("Çok fazla yönlendirme");
    }

    private static final class CookieJar {
        private final Map<String, String[]> cookies = new LinkedHashMap<>(); // ad|yol -> [ad, değer, yol]

        HttpRequest attach(HttpRequest request, URI uri) {
            String header = cookies.values().stream().filter(c -> uri.getPath().startsWith(c[2]))
                    .map(c -> c[0] + "=" + c[1]).collect(Collectors.joining("; "));
            if (header.isEmpty()) {
                return request;
            }
            HttpRequest.Builder copy = HttpRequest.newBuilder(request.uri()).method(request.method(),
                    request.bodyPublisher().orElse(HttpRequest.BodyPublishers.noBody()));
            request.headers().map().forEach((name, values) -> values.forEach(v -> copy.header(name, v)));
            return copy.header("Cookie", header).build();
        }

        void store(URI uri, HttpResponse<?> response) {
            for (String setCookie : response.headers().allValues("Set-Cookie")) {
                String[] parts = setCookie.split(";");
                int eq = parts[0].indexOf('=');
                String name = parts[0].substring(0, eq).trim();
                String value = parts[0].substring(eq + 1).trim();
                String path = "/";
                boolean expired = value.isEmpty();
                for (int i = 1; i < parts.length; i++) {
                    String attribute = parts[i].trim();
                    String lower = attribute.toLowerCase(java.util.Locale.ROOT);
                    if (lower.startsWith("path=")) {
                        path = attribute.substring(5);
                    } else if (lower.equals("max-age=0")) {
                        expired = true;
                    }
                }
                if (expired) {
                    cookies.remove(name + "|" + path);
                } else {
                    cookies.put(name + "|" + path, new String[]{name, value, path});
                }
            }
        }

        boolean has(String name, String pathPrefix) {
            return cookies.values().stream().anyMatch(c -> c[0].equals(name) && (c[2].startsWith(pathPrefix)
                    || pathPrefix.startsWith(c[2]) && !c[2].equals("/")));
        }
    }

    /* ======================= Keycloak kurulumu ======================= */

    private static void flow(String alias, List<String> authenticators, String requirement) throws Exception {
        adminPost("/admin/realms/app/authentication/flows", Map.of("alias", alias, "providerId", "basic-flow",
                "topLevel", true, "builtIn", false));
        for (String authenticator : authenticators) {
            adminPost("/admin/realms/app/authentication/flows/" + alias + "/executions/execution", Map.of("provider", authenticator));
        }
        for (JsonNode execution : adminGetArray("/admin/realms/app/authentication/flows/" + alias + "/executions")) {
            @SuppressWarnings("unchecked")
            Map<String, Object> update = JSON.convertValue(execution, Map.class);
            update.put("requirement", requirement);
            adminPut("/admin/realms/app/authentication/flows/" + alias + "/executions", update);
        }
    }

    private static void provider(String alias, String clientId, boolean trustEmail, String scope) throws Exception {
        String browserFacing = keycloakUrl() + "/realms/fakegoogle/protocol/openid-connect";
        String insideContainer = "http://localhost:8080/realms/fakegoogle/protocol/openid-connect";
        Map<String, String> config = new LinkedHashMap<>();
        config.put("clientId", clientId);
        config.put("clientSecret", "it-broker-secret");
        config.put("clientAuthMethod", "client_secret_post");
        config.put("authorizationUrl", browserFacing + "/auth");
        config.put("tokenUrl", insideContainer + "/token");
        config.put("defaultScope", scope);
        config.put("validateSignature", "false");
        config.put("syncMode", "IMPORT");
        Map<String, Object> provider = new LinkedHashMap<>();
        provider.put("alias", alias);
        provider.put("providerId", "oidc");
        provider.put("enabled", true);
        provider.put("trustEmail", trustEmail);
        provider.put("storeToken", false);
        provider.put("hideOnLogin", true);
        provider.put("firstBrokerLoginFlowAlias", "social-first-login");
        provider.put("postBrokerLoginFlowAlias", "social-post-login");
        provider.put("config", config);
        adminPost("/admin/realms/app/identity-provider/instances", provider);
    }

    private static Map<String, Object> hardcoded(String claim, String value, String type) {
        return Map.of("name", claim, "protocol", "openid-connect", "protocolMapper", "oidc-hardcoded-claim-mapper",
                "config", Map.of("claim.name", claim, "claim.value", value, "jsonType.label", type,
                        "id.token.claim", "true", "access.token.claim", "true", "userinfo.token.claim", "true"));
    }

    private static void hardcodedEmail(String email) throws Exception {
        String client = adminGetArray("/admin/realms/fakegoogle/clients?clientId=case-broker").get(0).get("id").asText();
        for (JsonNode mapper : adminGetArray("/admin/realms/fakegoogle/clients/" + client + "/protocol-mappers/models")) {
            if (mapper.get("name").asText().equals("email")) {
                @SuppressWarnings("unchecked")
                Map<String, Object> update = JSON.convertValue(mapper, Map.class);
                @SuppressWarnings("unchecked")
                Map<String, Object> config = (Map<String, Object>) update.get("config");
                config.put("claim.value", email);
                adminPut("/admin/realms/fakegoogle/clients/" + client + "/protocol-mappers/models/" + mapper.get("id").asText(), update);
            }
        }
    }

    private static void link(String userId, String alias, String providerUserId, String providerUserName) throws Exception {
        adminPost("/admin/realms/app/users/" + userId + "/federated-identity/" + alias,
                Map.of("identityProvider", alias, "userId", providerUserId, "userName", providerUserName));
    }

    /* ======================= yardımcılar ======================= */

    private static Path providersJar() {
        Path jar = Path.of(System.getProperty("it.providers.jar", "target/talay-keycloak-providers.jar"));
        if (!Files.isRegularFile(jar)) {
            throw new IllegalStateException("Eklenti JAR'ı yok: " + jar + " (./mvnw verify paketledikten sonra çalışır)");
        }
        return jar;
    }

    private static String keycloakUrl() {
        return "http://" + KEYCLOAK.getHost() + ":" + KEYCLOAK.getMappedPort(8080);
    }

    private static String newEmail() {
        return "it-" + UUID.randomUUID().toString().substring(0, 8) + "@ornek.test";
    }

    /** @return yeni kullanıcının kimliği */
    private static String createUser(String realm, String username, String email, boolean verified, String password) throws Exception {
        Map<String, Object> user = new LinkedHashMap<>();
        user.put("username", username);
        if (email != null) {
            user.put("email", email);
        }
        user.put("firstName", "Test");
        user.put("lastName", "Kişi");
        user.put("enabled", true);
        user.put("emailVerified", verified);
        if (password != null) {
            user.put("credentials", List.of(Map.of("type", "password", "value", password, "temporary", false)));
        }
        HttpResponse<String> response = HTTP.send(HttpRequest.newBuilder(URI.create(keycloakUrl() + "/admin/realms/" + realm + "/users"))
                .header("Authorization", "Bearer " + masterToken()).header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(JSON.writeValueAsString(user))).build(), HttpResponse.BodyHandlers.ofString());
        assertThat(response.statusCode()).as(response.body()).isEqualTo(201);
        String location = response.headers().firstValue("Location").orElseThrow();
        return location.substring(location.lastIndexOf('/') + 1);
    }

    private static List<JsonNode> usersWithEmail(String email) throws Exception {
        return adminGetArray("/admin/realms/app/users?exact=true&email=" + enc(email));
    }

    private static JsonNode exchange(String code) throws Exception {
        assertThat(code).isNotBlank();
        HttpResponse<String> response = HTTP.send(HttpRequest.newBuilder(URI.create(keycloakUrl() + "/realms/app/protocol/openid-connect/token"))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(formBody(Map.of("grant_type", "authorization_code",
                        "client_id", "app-gateway", "code", code, "redirect_uri", REDIRECT)))).build(), HttpResponse.BodyHandlers.ofString());
        assertThat(response.statusCode()).as(response.body()).isEqualTo(200);
        return JSON.readTree(response.body());
    }

    private static HttpResponse<String> passwordGrant(String username, String password) throws Exception {
        return HTTP.send(HttpRequest.newBuilder(URI.create(keycloakUrl() + "/realms/app/protocol/openid-connect/token"))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(formBody(Map.of("grant_type", "password", "client_id", "app-gateway",
                        "username", username, "password", password, "scope", "openid")))).build(), HttpResponse.BodyHandlers.ofString());
    }

    private static String subjectOf(JsonNode tokens) throws Exception {
        String payload = tokens.get("access_token").asText().split("\\.")[1];
        return JSON.readTree(Base64.getUrlDecoder().decode(payload)).get("sub").asText();
    }

    private static String masterToken() throws Exception {
        HttpResponse<String> response = HTTP.send(HttpRequest.newBuilder(URI.create(keycloakUrl() + "/realms/master/protocol/openid-connect/token"))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(formBody(Map.of("grant_type", "password", "client_id", "admin-cli",
                        "username", "admin", "password", "admin")))).build(), HttpResponse.BodyHandlers.ofString());
        return JSON.readTree(response.body()).get("access_token").asText();
    }

    private static JsonNode adminGet(String path) throws Exception {
        HttpResponse<String> response = HTTP.send(HttpRequest.newBuilder(URI.create(keycloakUrl() + path))
                .header("Authorization", "Bearer " + masterToken()).GET().build(), HttpResponse.BodyHandlers.ofString());
        assertThat(response.statusCode()).as(path + ": " + response.body()).isEqualTo(200);
        return JSON.readTree(response.body());
    }

    private static List<JsonNode> adminGetArray(String path) throws Exception {
        List<JsonNode> items = new ArrayList<>();
        adminGet(path).forEach(items::add);
        return items;
    }

    private static void adminPost(String path, Map<String, ?> body) throws Exception {
        send("POST", path, body);
    }

    private static void adminPut(String path, Map<String, ?> body) throws Exception {
        send("PUT", path, body);
    }

    private static void send(String method, String path, Map<String, ?> body) throws Exception {
        HttpResponse<String> response = HTTP.send(HttpRequest.newBuilder(URI.create(keycloakUrl() + path))
                .header("Authorization", "Bearer " + masterToken()).header("Content-Type", "application/json")
                .method(method, HttpRequest.BodyPublishers.ofString(JSON.writeValueAsString(body))).build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(response.statusCode()).as(method + " " + path + ": " + response.body()).isBetween(200, 204);
    }

    private static String formBody(Map<String, String> form) {
        return form.entrySet().stream().map(e -> enc(e.getKey()) + "=" + enc(e.getValue())).collect(Collectors.joining("&"));
    }

    private static Map<String, String> query(String rawQuery) {
        Map<String, String> values = new LinkedHashMap<>();
        if (rawQuery != null) {
            for (String pair : rawQuery.split("&")) {
                int eq = pair.indexOf('=');
                values.put(URLDecoder.decode(eq < 0 ? pair : pair.substring(0, eq), StandardCharsets.UTF_8),
                        eq < 0 ? "" : URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8));
            }
        }
        return values;
    }

    private static String enc(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
