package com.cantalay.keycloak.platform;

import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.UnaryOperator;
import java.util.stream.Collectors;

/**
 * Doğrulayıcı ayarları (Keycloak authenticator yapılandırması; Terraform yazar). Hesap bağlama ucu aynı ayarları
 * {@link #ALIAS} adlı yapılandırmadan okur.
 */
public record PlatformConfig(
        Set<String> gameCenterBundleIds,
        List<String> gameCenterKeyHosts,
        Duration gameCenterMaxAge,
        String playGamesClientId,
        String playGamesClientSecret,
        String playGamesTokenUrl,
        String playGamesPlayerUrl,
        boolean createUsers,
        String emailDomain,
        String lastName
) {
    /** Authenticator yapılandırmasının adı (hesap bağlama ucu bunu arar). */
    public static final String ALIAS = "platform-identity";

    public static final String BUNDLE_IDS = "gameCenterBundleIds";
    public static final String KEY_HOSTS = "gameCenterKeyHosts";
    public static final String MAX_AGE = "gameCenterMaxAgeSeconds";
    public static final String PG_CLIENT_ID = "playGamesClientId";
    public static final String PG_CLIENT_SECRET = "playGamesClientSecret";
    public static final String PG_TOKEN_URL = "playGamesTokenUrl";
    public static final String PG_PLAYER_URL = "playGamesPlayerUrl";
    public static final String CREATE_USERS = "createUsers";
    public static final String EMAIL_DOMAIN = "emailDomain";
    public static final String LAST_NAME = "lastName";

    public static final String DEFAULT_KEY_HOSTS = "apple.com";
    public static final String DEFAULT_TOKEN_URL = "https://oauth2.googleapis.com/token";
    public static final String DEFAULT_PLAYER_URL = "https://games.googleapis.com/games/v1/players/me";

    public static PlatformConfig from(Map<String, String> config) {
        return from(config, UnaryOperator.identity());
    }

    /**
     * @param secrets sır alanının çözümü: Keycloak kasası ("${vault.anahtar}" → dosyadaki değer); sır Terraform durumuna düşmez.
     */
    public static PlatformConfig from(Map<String, String> config, UnaryOperator<String> secrets) {
        Map<String, String> c = config == null ? Map.of() : config;
        return new PlatformConfig(
                split(c.get(BUNDLE_IDS)).stream().collect(Collectors.toUnmodifiableSet()),
                split(c.getOrDefault(KEY_HOSTS, DEFAULT_KEY_HOSTS)),
                Duration.ofSeconds(parseLong(c.get(MAX_AGE), 900)),
                blankToNull(c.get(PG_CLIENT_ID)),
                blankToNull(c.get(PG_CLIENT_SECRET) == null ? null : secrets.apply(c.get(PG_CLIENT_SECRET))),
                orDefault(c.get(PG_TOKEN_URL), DEFAULT_TOKEN_URL),
                orDefault(c.get(PG_PLAYER_URL), DEFAULT_PLAYER_URL),
                !"false".equalsIgnoreCase(c.get(CREATE_USERS)),
                orDefault(c.get(EMAIL_DOMAIN), "platform.invalid"),
                orDefault(c.get(LAST_NAME), "Player"));
    }

    public boolean gameCenterEnabled() {
        return !gameCenterBundleIds.isEmpty();
    }

    public boolean playGamesEnabled() {
        return playGamesClientId != null && playGamesClientSecret != null;
    }

    private static List<String> split(String value) {
        if (value == null || value.isBlank()) return List.of();
        return Arrays.stream(value.split(",")).map(String::trim).filter(s -> !s.isEmpty()).toList();
    }

    private static long parseLong(String value, long fallback) {
        try {
            return value == null || value.isBlank() ? fallback : Long.parseLong(value.trim());
        } catch (NumberFormatException e) {
            return fallback;
        }
    }

    private static String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }

    private static String orDefault(String value, String fallback) {
        return value == null || value.isBlank() ? fallback : value.trim();
    }
}
