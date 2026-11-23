package com.cantalay.keycloak.broker;

import jakarta.ws.rs.core.Response;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.events.Errors;
import org.keycloak.protocol.LoginProtocol;
import org.keycloak.sessions.AuthenticationSessionModel;

/**
 * Sosyal girişi Keycloak sayfası göstermeden reddeder: tarayıcı istemcinin (doğrulanmış) dönüş adresine OAuth hata yanıtıyla
 * gider, {@code error=access_denied&error_description=<neden>&state=...} (RFC 6749 §4.1.2.1; Keycloak'ın "vazgeç" yanıtıyla
 * aynı yol, {@code AuthenticationFlowContext#cancelLogin}). Kod üretilmez, kullanıcı oturumu açılmaz, SSO çerezi yazılmaz.
 * auth-gateway {@code /social} bu nedeni {@code {error, errorDescription}} olarak alıp 409'a çevirir.
 */
final class BrokerRefusal {

    /** Aynı e-postalı, e-postası onaylanmamış bir hesap var: bağlanmadı (önceden hesap ele geçirmeye karşı). */
    static final String ACCOUNT_EXISTS_UNVERIFIED = "account_exists_unverified";
    /**
     * Hesap var ama bu sağlayıcı kimliği ona bağlanamaz: sağlayıcı e-postayı doğrulamadı ya da yalnız kullanıcı adı
     * çakıştı (e-postalar farklı).
     */
    static final String ACCOUNT_EXISTS = "account_exists";

    private BrokerRefusal() {
    }

    static void refuse(AuthenticationFlowContext context, String reason) {
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        context.getEvent().detail("reason", reason).error(Errors.FEDERATED_IDENTITY_EXISTS);
        LoginProtocol protocol = context.getSession().getProvider(LoginProtocol.class, authSession.getProtocol());
        protocol.setRealm(context.getRealm())
                .setHttpHeaders(context.getHttpRequest().getHttpHeaders())
                .setUriInfo(context.getUriInfo())
                .setEventBuilder(context.getEvent());
        Response response = protocol.sendError(authSession, LoginProtocol.Error.CANCELLED_BY_USER, reason);
        context.forceChallenge(response);
    }
}
