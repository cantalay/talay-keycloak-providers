package com.cantalay.keycloak.platform;

/** Platform belirteci doğrulanamadı (imza, süre, paket kimliği, Google yanıtı). Mesaj günlüğe gider, istemciye gitmez. */
public final class PlatformVerificationException extends Exception {
    public PlatformVerificationException(String message) {
        super(message);
    }

    public PlatformVerificationException(String message, Throwable cause) {
        super(message, cause);
    }
}
