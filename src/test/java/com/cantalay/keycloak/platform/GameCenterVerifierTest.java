package com.cantalay.keycloak.platform;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.Signature;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class GameCenterVerifierTest {
    private static final String BUNDLE = "com.cantalay.colonyconquest";
    private static final String URL = "https://static.gc.apple.com/public-key/gc-prod-10.cer";
    private static TestKeys.Pair apple;
    private static TestKeys.Pair other;
    private final Instant now = Instant.parse("2026-10-25T10:00:00Z");
    private final Clock clock = Clock.fixed(now, ZoneOffset.UTC);
    private final PlatformConfig config = PlatformConfig.from(Map.of(PlatformConfig.BUNDLE_IDS, BUNDLE));

    @BeforeAll
    static void keys() throws Exception {
        apple = TestKeys.generate("CN=Test Game Center Key, O=Apple Inc., C=US");
        other = TestKeys.generate("CN=Not Apple, O=Evil Corp, C=US");
    }

    @BeforeEach
    void clear() {
        GameCenterVerifier.clearCache();
    }

    private String token(TestKeys.Pair key, String url, String bundle, long timestamp, String player) throws Exception {
        byte[] salt = {1, 2, 3, 4, 5, 6, 7, 8};
        byte[] p = player.getBytes(StandardCharsets.UTF_8);
        byte[] b = bundle.getBytes(StandardCharsets.UTF_8);
        ByteBuffer data = ByteBuffer.allocate(p.length + b.length + 8 + salt.length).put(p).put(b).putLong(timestamp).put(salt);
        Signature s = Signature.getInstance("SHA256withRSA");
        s.initSign(key.key());
        s.update(data.array());
        String json = "{\"publicKeyUrl\":\"" + url + "\",\"signature\":\"" + Base64.getEncoder().encodeToString(s.sign())
                + "\",\"salt\":\"" + Base64.getEncoder().encodeToString(salt) + "\",\"timestamp\":" + timestamp
                + ",\"teamPlayerId\":\"" + player + "\",\"bundleId\":\"" + bundle + "\",\"displayName\":\"Kaptan\"}";
        return Base64.getUrlEncoder().withoutPadding().encodeToString(json.getBytes(StandardCharsets.UTF_8));
    }

    private GameCenterVerifier verifier(TestKeys.Pair served) {
        return new GameCenterVerifier(config, clock, uri -> served.certificate(), true);
    }

    @Test
    void validSignatureGivesTheTeamPlayerId() throws Exception {
        PlatformIdentity id = verifier(apple).verify(token(apple, URL, BUNDLE, now.toEpochMilli() - 5_000, "T:_abc123"));
        assertThat(id.platform()).isEqualTo(Platforms.GAME_CENTER);
        assertThat(id.subject()).isEqualTo("T:_abc123");
        assertThat(id.displayName()).isEqualTo("Kaptan");
    }

    @Test
    void tamperedPlayerIdIsRejected() throws Exception {
        String good = new String(Base64.getUrlDecoder().decode(token(apple, URL, BUNDLE, now.toEpochMilli(), "T:_abc123")), StandardCharsets.UTF_8);
        String forged = good.replace("T:_abc123", "T:_victim");
        assertThatThrownBy(() -> verifier(apple).verify(forged)).isInstanceOf(PlatformVerificationException.class).hasMessageContaining("imza");
    }

    @Test
    void otherBundleOldSignatureAndForeignKeysAreRejected() throws Exception {
        assertThatThrownBy(() -> verifier(apple).verify(token(apple, URL, "com.other.app", now.toEpochMilli(), "T:1")))
                .hasMessageContaining("paket");
        assertThatThrownBy(() -> verifier(apple).verify(token(apple, URL, BUNDLE, now.toEpochMilli() - 3_600_000, "T:1")))
                .hasMessageContaining("zaman");
        // Apple'ın olmayan sertifika (imza kendi anahtarıyla doğru olsa da).
        assertThatThrownBy(() -> verifier(other).verify(token(other, URL, BUNDLE, now.toEpochMilli(), "T:1")))
                .hasMessageContaining("Apple");
        // Sunulan sertifikanın anahtarıyla imzalanmamış (sertifika önbelleği adres başınadır).
        GameCenterVerifier.clearCache();
        assertThatThrownBy(() -> verifier(apple).verify(token(other, URL, BUNDLE, now.toEpochMilli(), "T:1")))
                .hasMessageContaining("imza");
    }

    @Test
    void keyUrlMustBeHttpsOnAnAllowedHost() throws Exception {
        GameCenterVerifier v = verifier(apple);
        assertThat(v.keyUri(URL).getHost()).isEqualTo("static.gc.apple.com");
        for (String bad : new String[] {
                "http://static.gc.apple.com/k.cer", "https://apple.com.evil.example/k.cer", "https://evilapple.com/k.cer",
                "https://user@static.gc.apple.com/k.cer", "https://static.gc.apple.com:8443/k.cer", "file:///etc/passwd"}) {
            assertThatThrownBy(() -> v.keyUri(bad)).as(bad).isInstanceOf(PlatformVerificationException.class);
        }
    }

    @Test
    void disabledWithoutBundleIdsAndMalformedTokens() {
        GameCenterVerifier off = new GameCenterVerifier(PlatformConfig.from(Map.of()), clock, uri -> apple.certificate(), true);
        assertThatThrownBy(() -> off.verify("{}")).hasMessageContaining("kapalı");
        assertThatThrownBy(() -> verifier(apple).verify("%%%")).isInstanceOf(PlatformVerificationException.class);
        assertThatThrownBy(() -> verifier(apple).verify("{\"bundleId\":\"x\"}")).hasMessageContaining("eksik");
    }
}
