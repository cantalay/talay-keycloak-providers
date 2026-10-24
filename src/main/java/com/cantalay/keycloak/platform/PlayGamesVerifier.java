package com.cantalay.keycloak.platform;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.keycloak.util.JsonSerialization;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Play Games Services v2 sunucu erişimi: istemci GamesSignInClient.requestServerSideAccess(webClientId) ile tek kullanımlık kod
 * alır; burada Google'ın token ucunda erişim belirtecine çevrilir ve Games API'den (players/me) oyuncu kimliği okunur. Kod bir kez
 * kullanılabildiği için yeniden oynatılamaz.
 */
public final class PlayGamesVerifier {

    @JsonIgnoreProperties(ignoreUnknown = true)
    static final class TokenResponse {
        @JsonProperty("access_token")
        public String accessToken;
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    static final class Player {
        public String playerId;
        public String displayName;
    }

    private final PlatformConfig config;
    private final HttpClient http;

    public PlayGamesVerifier(PlatformConfig config) {
        this(config, HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).followRedirects(HttpClient.Redirect.NEVER).build());
    }

    PlayGamesVerifier(PlatformConfig config, HttpClient http) {
        this.config = config;
        this.http = http;
    }

    public PlatformIdentity verify(String serverAuthCode) throws PlatformVerificationException {
        if (!config.playGamesEnabled()) throw new PlatformVerificationException("Play Games kapalı (istemci kimliği/sırrı yok)");
        if (serverAuthCode == null || serverAuthCode.isBlank() || serverAuthCode.length() > 2048)
            throw new PlatformVerificationException("kod boş ya da çok uzun");
        Map<String, String> form = new LinkedHashMap<>();
        form.put("grant_type", "authorization_code");
        form.put("code", serverAuthCode.trim());
        form.put("client_id", config.playGamesClientId());
        form.put("client_secret", config.playGamesClientSecret());
        form.put("redirect_uri", "");
        String body = form.entrySet().stream()
                .map(e -> URLEncoder.encode(e.getKey(), StandardCharsets.UTF_8) + "=" + URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8))
                .collect(Collectors.joining("&"));
        TokenResponse token = send(HttpRequest.newBuilder(URI.create(config.playGamesTokenUrl()))
                .timeout(Duration.ofSeconds(10))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build(), TokenResponse.class, "token");
        if (token.accessToken == null || token.accessToken.isBlank()) throw new PlatformVerificationException("Google erişim belirteci vermedi");
        Player player = send(HttpRequest.newBuilder(URI.create(config.playGamesPlayerUrl()))
                .timeout(Duration.ofSeconds(10))
                .header("Authorization", "Bearer " + token.accessToken)
                .GET()
                .build(), Player.class, "players/me");
        if (player.playerId == null || player.playerId.isBlank()) throw new PlatformVerificationException("oyuncu kimliği yok");
        return new PlatformIdentity(Platforms.PLAY_GAMES, player.playerId, player.displayName == null ? "" : player.displayName);
    }

    private <T> T send(HttpRequest request, Class<T> type, String what) throws PlatformVerificationException {
        try {
            HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) throw new PlatformVerificationException("Google " + what + " HTTP " + response.statusCode());
            return JsonSerialization.readValue(response.body(), type);
        } catch (PlatformVerificationException e) {
            throw e;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new PlatformVerificationException("Google " + what + " kesildi", e);
        } catch (Exception e) {
            throw new PlatformVerificationException("Google " + what + " okunamadı", e);
        }
    }
}
