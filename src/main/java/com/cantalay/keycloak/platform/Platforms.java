package com.cantalay.keycloak.platform;

import java.util.Locale;

/** Desteklenen platformlar ve kullanıcıda tutulan öznitelik adları. */
public final class Platforms {
    public static final String GAME_CENTER = "gamecenter";
    public static final String PLAY_GAMES = "playgames";

    private Platforms() {
    }

    /** Kullanıcı özniteliği: platformun oyuncu kimliği (bir kullanıcıya bağlı, tekil). */
    public static String attribute(String platform) {
        return "platform." + platform;
    }

    /** Yeni kullanıcının ön eki ("gc-…", "pg-…"). */
    static String usernamePrefix(String platform) {
        return GAME_CENTER.equals(platform) ? "gc-" : "pg-";
    }

    /** Bilinmeyen platform için null. */
    public static String normalize(String platform) {
        if (platform == null) return null;
        String p = platform.trim().toLowerCase(Locale.ROOT);
        return GAME_CENTER.equals(p) || PLAY_GAMES.equals(p) ? p : null;
    }
}
