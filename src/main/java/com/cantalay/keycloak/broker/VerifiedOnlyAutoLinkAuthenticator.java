package com.cantalay.keycloak.broker;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.authenticators.broker.AbstractIdpAuthenticator;
import org.keycloak.authentication.authenticators.broker.util.SerializedBrokeredIdentityContext;
import org.keycloak.broker.oidc.OIDCIdentityProvider;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.representations.IDToken;
import org.keycloak.representations.JsonWebToken;

import java.util.Map;

/**
 * İlk sosyal girişte ({@code first broker login}) aynı e-postalı hesaba yalnız güvenliyse otomatik bağlar; Keycloak'ın
 * {@code idp-auto-link}'inin ("hiç doğrulamadan") yerine, {@code idp-create-user-if-unique} ile ALTERNATIVE kullanılır.
 * <p>
 * Bağlama koşulları (hepsi):
 * <ul>
 *     <li>mevcut hesabın e-postası onaylı ({@code emailVerified}): adresin sahibi olduğunu kanıtlamış. Onaysızsa adresi kim
 *     yazdıysa parolası ondadır; Google'ı ona bağlamak önceden hesap ele geçirmedir (saldırgan kurbanın adresiyle parolalı
 *     kayıt olur, kurban Google ile girince saldırganın bildiği hesaba düşer);</li>
 *     <li>sağlayıcının verdiği e-posta mevcut hesabınkiyle aynı (büyük/küçük harf duyarsız). Yalnız kullanıcı adı çakıştıysa
 *     bağlanmaz;</li>
 *     <li>sağlayıcı e-postaya kefil: kimlik sağlayıcıda {@code trustEmail} açık ve kimlik belirtecinde
 *     {@code email_verified=false} yok.</li>
 * </ul>
 * Tutmazsa bağlamaz, kullanıcı oluşturmaz ve akışı istemcinin dönüş adresine
 * {@code error=access_denied&error_description=account_exists_unverified} (ya da {@code account_exists}) ile bitirir
 * ({@link BrokerRefusal}).
 */
public final class VerifiedOnlyAutoLinkAuthenticator extends AbstractIdpAuthenticator {

    private static final Logger LOG = Logger.getLogger(VerifiedOnlyAutoLinkAuthenticator.class);

    @Override
    protected void authenticateImpl(AuthenticationFlowContext context, SerializedBrokeredIdentityContext serializedCtx,
                                    BrokeredIdentityContext brokerContext) {
        KeycloakSession session = context.getSession();
        RealmModel realm = context.getRealm();
        UserModel existing = getExistingUser(session, realm, context.getAuthenticationSession());
        String alias = brokerContext.getIdpConfig().getAlias();

        String reason = refusal(existing, brokerContext);
        if (reason != null) {
            LOG.infof("Sosyal giriş bağlanmadı (realm %s, sağlayıcı %s, kullanıcı %s): %s", realm.getName(), alias,
                    existing.getId(), reason);
            context.getEvent().user(existing);
            BrokerRefusal.refuse(context, reason);
            return;
        }
        LOG.debugf("Sağlayıcı %s, onaylı e-postalı kullanıcı %s ile bağlanıyor (realm %s)", alias, existing.getId(), realm.getName());
        context.setUser(existing);
        context.success();
    }

    /** @return ret nedeni; bağlanabilirse {@code null} */
    static String refusal(UserModel existing, BrokeredIdentityContext brokerContext) {
        if (!sameEmail(existing.getEmail(), brokerContext.getEmail()) || !providerVouchesForEmail(brokerContext)) {
            return BrokerRefusal.ACCOUNT_EXISTS;
        }
        if (!existing.isEmailVerified()) {
            return BrokerRefusal.ACCOUNT_EXISTS_UNVERIFIED;
        }
        return null;
    }

    /** Büyük/küçük harf duyarsız, yerelden bağımsız (Türkçe "I/ı" dönüşümü yok). */
    static boolean sameEmail(String local, String brokered) {
        if (local == null || brokered == null || local.isBlank() || brokered.isBlank()) {
            return false;
        }
        return local.strip().equalsIgnoreCase(brokered.strip());
    }

    /**
     * Sağlayıcı e-postaya kefil mi: {@code trustEmail} açık ve doğrulanmış kimlik belirtecinde (yoksa erişim belirtecinde)
     * {@code email_verified} false değil. Keycloak'ın yeni kullanıcıda {@code emailVerified} için kullandığı kuralla aynı
     * ({@code OIDCIdentityProvider#setEmailVerified}): iddia yoksa {@code trustEmail} belirler.
     */
    static boolean providerVouchesForEmail(BrokeredIdentityContext brokerContext) {
        if (!Boolean.TRUE.equals(brokerContext.getIdpConfig().isTrustEmail())) {
            return false;
        }
        Map<String, Object> data = brokerContext.getContextData();
        Object token = data.get(OIDCIdentityProvider.VALIDATED_ID_TOKEN);
        if (!(token instanceof JsonWebToken)) {
            token = data.get(OIDCIdentityProvider.VALIDATED_ACCESS_TOKEN);
        }
        if (token instanceof JsonWebToken jwt) {
            Object claim = jwt.getOtherClaims().get(IDToken.EMAIL_VERIFIED);
            return claim == null || Boolean.parseBoolean(claim.toString());
        }
        return true;
    }

    @Override
    protected void actionImpl(AuthenticationFlowContext context, SerializedBrokeredIdentityContext serializedCtx,
                              BrokeredIdentityContext brokerContext) {
        authenticateImpl(context, serializedCtx, brokerContext);
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return false;
    }
}
