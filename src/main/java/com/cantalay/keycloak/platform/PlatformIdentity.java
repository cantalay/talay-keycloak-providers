package com.cantalay.keycloak.platform;

/**
 * Doğrulanmış platform kimliği.
 *
 * @param platform    {@link Platforms#GAME_CENTER} ya da {@link Platforms#PLAY_GAMES}
 * @param subject     platformun oyuncu kimliği (Game Center teamPlayerID, Play Games playerId)
 * @param displayName platformdaki görünen ad (boş olabilir; yalnız yeni kullanıcının adı için)
 */
public record PlatformIdentity(String platform, String subject, String displayName) {
}
