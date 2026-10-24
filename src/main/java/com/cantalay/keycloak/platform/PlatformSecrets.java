package com.cantalay.keycloak.platform;

import org.keycloak.models.KeycloakSession;
import org.keycloak.vault.VaultStringSecret;

import java.util.function.UnaryOperator;

/** Yapılandırmadaki "${vault.anahtar}" referansını Keycloak kasasından çözer; referans değilse değer olduğu gibi kalır. */
final class PlatformSecrets {
    private PlatformSecrets() {
    }

    static UnaryOperator<String> of(KeycloakSession session) {
        return value -> {
            if (value == null || !value.startsWith("${vault.")) return value;
            try (VaultStringSecret secret = session.vault().getStringSecret(value)) {
                return secret.get().orElse(null);
            }
        };
    }
}
