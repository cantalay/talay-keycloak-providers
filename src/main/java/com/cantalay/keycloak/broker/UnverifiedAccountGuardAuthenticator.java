package com.cantalay.keycloak.broker;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.PasswordCredentialModel;

/**
 * Sosyal girişten sonra ({@code post broker login} akışı; her sosyal girişte, bağ eskiden kurulmuş olsa da çalışır):
 * parolası olan ve e-postası onaylanmamış hesaba sosyal girişle oturum açılmaz. Eski {@code idp-auto-link} döneminde ya da
 * elle kurulmuş bağlar böyle bir hesaba düşebilir; adresi kim yazdıysa parolası ondadır. Ret {@link BrokerRefusal} ile
 * ({@code error_description=account_exists_unverified}): oturum açılmaz, SSO çerezi yazılmaz, bağa dokunulmaz.
 * <p>
 * Parolasız hesaplar (sağlayıcıyla açılmış, Game Center / Play Games) etkilenmez: onların tek giriş yolu sağlayıcıdır.
 */
public final class UnverifiedAccountGuardAuthenticator implements Authenticator {

    private static final Logger LOG = Logger.getLogger(UnverifiedAccountGuardAuthenticator.class);

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        UserModel user = context.getUser();
        if (user != null && refuses(user)) {
            LOG.infof("Sosyal giriş reddedildi (realm %s, kullanıcı %s): parolalı hesabın e-postası onaylanmamış",
                    context.getRealm().getName(), user.getId());
            BrokerRefusal.refuse(context, BrokerRefusal.ACCOUNT_EXISTS_UNVERIFIED);
            return;
        }
        context.success();
    }

    static boolean refuses(UserModel user) {
        return !user.isEmailVerified() && user.credentialManager().isConfiguredFor(PasswordCredentialModel.TYPE);
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        authenticate(context);
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
    }

    @Override
    public void close() {
    }
}
