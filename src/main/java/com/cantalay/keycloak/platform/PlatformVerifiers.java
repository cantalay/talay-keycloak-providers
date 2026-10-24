package com.cantalay.keycloak.platform;

/** Platforma göre doğrulayıcı. */
final class PlatformVerifiers {
    private PlatformVerifiers() {
    }

    static PlatformIdentity verify(PlatformConfig config, String platform, String token) throws PlatformVerificationException {
        String p = Platforms.normalize(platform);
        if (p == null) throw new PlatformVerificationException("bilinmeyen platform: " + platform);
        return Platforms.GAME_CENTER.equals(p) ? new GameCenterVerifier(config).verify(token) : new PlayGamesVerifier(config).verify(token);
    }
}
