package com.cantalay.keycloak.platform;

import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.List;

/** Platform kimliği ↔ Keycloak kullanıcısı: kullanıcı özniteliği "platform.&lt;platform&gt;" = oyuncu kimliği (tekil). */
final class PlatformUsers {
    private PlatformUsers() {
    }

    /** Bu platform kimliğine bağlı kullanıcı; yoksa null. Birden çok bulunursa (elle bozulmuş veri) en eskisi. */
    static UserModel find(KeycloakSession session, RealmModel realm, PlatformIdentity identity) {
        List<UserModel> users = session.users()
                .searchForUserByUserAttributeStream(realm, Platforms.attribute(identity.platform()), identity.subject())
                .toList();
        return users.stream().min((a, b) -> Long.compare(created(a), created(b))).orElse(null);
    }

    /** Yeni kullanıcı (e-postasız, parolasız): kullanıcı adı "gc-…"/"pg-…" + kimliğin özeti; kimlik özniteliğe bağlanır. */
    static UserModel create(KeycloakSession session, RealmModel realm, PlatformIdentity identity, PlatformConfig config) {
        String base = Platforms.usernamePrefix(identity.platform()) + digest(identity.subject()).substring(0, 16);
        String username = base;
        for (int i = 2; session.users().getUserByUsername(realm, username) != null; i++) username = base + "-" + i;
        UserModel user = session.users().addUser(realm, username);
        user.setEnabled(true);
        // Bildirimsel kullanıcı profili e-posta ve ad/soyad ister (yoksa "Account is not fully set up"): misafir hesapları gibi
        // sentetik, doğrulanmış e-posta; ad platformdaki görünen ad.
        complete(user, identity, config);
        link(user, identity);
        return user;
    }

    /** Kullanıcı profilinin istediği boş alanları doldurur (dolu alana dokunmaz; bağlanmış e-posta hesabı değişmez). */
    static void complete(UserModel user, PlatformIdentity identity, PlatformConfig config) {
        if (user.getEmail() == null || user.getEmail().isBlank()) {
            user.setEmail(user.getUsername() + "@" + config.emailDomain());
            user.setEmailVerified(true);
        }
        if (user.getFirstName() == null || user.getFirstName().isBlank()) {
            String name = identity.displayName() == null || identity.displayName().isBlank() ? "Player" : identity.displayName().strip();
            user.setFirstName(name.length() > 64 ? name.substring(0, 64) : name);
        }
        if (user.getLastName() == null || user.getLastName().isBlank()) user.setLastName(config.lastName());
    }

    static void link(UserModel user, PlatformIdentity identity) {
        user.setSingleAttribute(Platforms.attribute(identity.platform()), identity.subject());
    }

    static void unlink(UserModel user, String platform) {
        user.removeAttribute(Platforms.attribute(platform));
    }

    private static long created(UserModel user) {
        Long t = user.getCreatedTimestamp();
        return t == null ? Long.MAX_VALUE : t;
    }

    static String digest(String value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
