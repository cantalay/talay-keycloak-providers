package com.cantalay.keycloak.platform;

import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class PlayGamesVerifierTest {
    private HttpServer server;
    private final AtomicReference<Map<String, String>> lastForm = new AtomicReference<>();
    private final AtomicReference<String> lastAuth = new AtomicReference<>();
    private volatile int tokenStatus = 200;

    @BeforeEach
    void start() throws Exception {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/token", ex -> {
            String body = new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            Map<String, String> form = new HashMap<>();
            for (String kv : body.split("&")) {
                String[] p = kv.split("=", 2);
                form.put(URLDecoder.decode(p[0], StandardCharsets.UTF_8), p.length > 1 ? URLDecoder.decode(p[1], StandardCharsets.UTF_8) : "");
            }
            lastForm.set(form);
            byte[] out = "{\"access_token\":\"ya29.test\",\"token_type\":\"Bearer\"}".getBytes(StandardCharsets.UTF_8);
            ex.sendResponseHeaders(tokenStatus, out.length);
            ex.getResponseBody().write(out);
            ex.close();
        });
        server.createContext("/players/me", ex -> {
            lastAuth.set(ex.getRequestHeaders().getFirst("Authorization"));
            byte[] out = "{\"kind\":\"games#player\",\"playerId\":\"g0123456789\",\"displayName\":\"Akıncı\"}".getBytes(StandardCharsets.UTF_8);
            ex.sendResponseHeaders(200, out.length);
            ex.getResponseBody().write(out);
            ex.close();
        });
        server.start();
    }

    @AfterEach
    void stop() {
        server.stop(0);
    }

    private PlatformConfig config() {
        String base = "http://127.0.0.1:" + server.getAddress().getPort();
        return PlatformConfig.from(Map.of(
                PlatformConfig.PG_CLIENT_ID, "web-client.apps.googleusercontent.com",
                PlatformConfig.PG_CLIENT_SECRET, "test-only-secret",
                PlatformConfig.PG_TOKEN_URL, base + "/token",
                PlatformConfig.PG_PLAYER_URL, base + "/players/me"));
    }

    @Test
    void serverAuthCodeIsExchangedAndThePlayerIdRead() throws Exception {
        PlatformIdentity id = new PlayGamesVerifier(config()).verify("4/0Aserver-code");
        assertThat(id.platform()).isEqualTo(Platforms.PLAY_GAMES);
        assertThat(id.subject()).isEqualTo("g0123456789");
        assertThat(id.displayName()).isEqualTo("Akıncı");
        assertThat(lastForm.get()).containsEntry("grant_type", "authorization_code").containsEntry("code", "4/0Aserver-code")
                .containsEntry("client_id", "web-client.apps.googleusercontent.com").containsEntry("client_secret", "test-only-secret");
        assertThat(lastAuth.get()).isEqualTo("Bearer ya29.test");
    }

    @Test
    void googleErrorsAndDisabledConfigAreRejected() {
        tokenStatus = 400;
        assertThatThrownBy(() -> new PlayGamesVerifier(config()).verify("used-code")).hasMessageContaining("HTTP 400");
        assertThatThrownBy(() -> new PlayGamesVerifier(PlatformConfig.from(Map.of())).verify("x")).hasMessageContaining("kapalı");
        assertThatThrownBy(() -> new PlayGamesVerifier(config()).verify(" ")).hasMessageContaining("boş");
    }
}
