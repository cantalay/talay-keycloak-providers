package com.cantalay.keycloak.platform;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.authenticators.directgrant.AbstractDirectGrantAuthenticator;
import org.keycloak.events.Errors;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.List;

/**
 * Game Center / Play Games kimliğiyle giriş (direct grant). İstemci, giriş akışı bu authenticator'a bağlı istemciyle
 * (ör. conquest-platform) {@code grant_type=password&platform=gamecenter|playgames&platform_token=...} gönderir. Kimlik doğrulanır,
 * bağlı kullanıcı bulunur (yoksa yapılandırma izin veriyorsa oluşturulur) ve Keycloak her zamanki token'ları verir (offline_access
 * isteniyorsa offline token). Doğrulama ayrıntısı günlükte kalır; istemciye yalnız "invalid_grant" gider.
 */
public final class PlatformIdentityAuthenticator extends AbstractDirectGrantAuthenticator {

    public static final String PROVIDER_ID = "platform-identity";
    private static final Logger LOG = Logger.getLogger(PlatformIdentityAuthenticator.class);

    private static final AuthenticationExecutionModel.Requirement[] REQUIREMENTS = {
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.DISABLED,
    };

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> form = context.getHttpRequest().getDecodedFormParameters();
        String platform = Platforms.normalize(form.getFirst("platform"));
        String token = form.getFirst("platform_token");
        if (platform == null || token == null || token.isBlank()) {
            context.getEvent().error(Errors.INVALID_USER_CREDENTIALS);
            Response challenge = errorResponse(Response.Status.BAD_REQUEST.getStatusCode(), "invalid_request", "platform ve platform_token gerekli");
            context.failure(AuthenticationFlowError.INVALID_CREDENTIALS, challenge);
            return;
        }
        PlatformConfig config = PlatformConfig.from(context.getAuthenticatorConfig() == null ? null : context.getAuthenticatorConfig().getConfig());
        PlatformIdentity identity;
        try {
            identity = PlatformVerifiers.verify(config, platform, token);
        } catch (PlatformVerificationException e) {
            LOG.warnf("Platform girişi reddedildi (%s, realm %s): %s", platform, context.getRealm().getName(), e.getMessage());
            context.getEvent().detail("platform", platform).error(Errors.INVALID_USER_CREDENTIALS);
            Response challenge = errorResponse(Response.Status.UNAUTHORIZED.getStatusCode(), "invalid_grant", "Platform kimliği doğrulanamadı");
            context.failure(AuthenticationFlowError.INVALID_CREDENTIALS, challenge);
            return;
        }
        KeycloakSession session = context.getSession();
        RealmModel realm = context.getRealm();
        UserModel user = PlatformUsers.find(session, realm, identity);
        boolean created = false;
        if (user == null && config.createUsers()) {
            user = PlatformUsers.create(session, realm, identity, config);
            created = true;
        }
        if (user == null) {
            context.getEvent().detail("platform", platform).error(Errors.USER_NOT_FOUND);
            Response challenge = errorResponse(Response.Status.UNAUTHORIZED.getStatusCode(), "invalid_grant", "Bu platform kimliğine bağlı hesap yok");
            context.failure(AuthenticationFlowError.INVALID_USER, challenge);
            return;
        }
        if (!user.isEnabled()) {
            context.getEvent().user(user).error(Errors.USER_DISABLED);
            Response challenge = errorResponse(Response.Status.BAD_REQUEST.getStatusCode(), "invalid_grant", "Account disabled");
            context.failure(AuthenticationFlowError.USER_DISABLED, challenge);
            return;
        }
        PlatformUsers.complete(user, identity, config);
        context.getEvent().detail("platform", platform).detail("platform_user_created", Boolean.toString(created));
        context.setUser(user);
        context.success();
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "Platform Identity (Game Center / Play Games)";
    }

    @Override
    public String getReferenceCategory() {
        return "platform";
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENTS;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public String getHelpText() {
        return "Game Center kimlik doğrulama imzasıyla ya da Play Games sunucu koduyla giriş; kimlik kullanıcı özniteliğine bağlanır.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return List.of(
                property(PlatformConfig.BUNDLE_IDS, "Game Center bundle IDs", "İzinli iOS paket kimlikleri (virgülle). Boşsa Game Center kapalı.",
                        ProviderConfigProperty.STRING_TYPE, null),
                property(PlatformConfig.KEY_HOSTS, "Game Center key hosts", "İmza sertifikasının izinli alan adları (virgülle).",
                        ProviderConfigProperty.STRING_TYPE, PlatformConfig.DEFAULT_KEY_HOSTS),
                property(PlatformConfig.MAX_AGE, "Game Center max age (s)", "İmzanın en çok yaşı (yeniden oynatmaya karşı).",
                        ProviderConfigProperty.STRING_TYPE, "900"),
                property(PlatformConfig.PG_CLIENT_ID, "Play Games web client ID", "Google OAuth web istemci kimliği. Boşsa Play Games kapalı.",
                        ProviderConfigProperty.STRING_TYPE, null),
                property(PlatformConfig.PG_CLIENT_SECRET, "Play Games client secret", "Google OAuth istemci sırrı.",
                        ProviderConfigProperty.PASSWORD, null),
                property(PlatformConfig.PG_TOKEN_URL, "Play Games token URL", "Google token ucu.",
                        ProviderConfigProperty.STRING_TYPE, PlatformConfig.DEFAULT_TOKEN_URL),
                property(PlatformConfig.PG_PLAYER_URL, "Play Games player URL", "Games API oyuncu ucu.",
                        ProviderConfigProperty.STRING_TYPE, PlatformConfig.DEFAULT_PLAYER_URL),
                property(PlatformConfig.CREATE_USERS, "Create users", "Bağlı hesap yoksa yeni kullanıcı oluştur.",
                        ProviderConfigProperty.BOOLEAN_TYPE, "true"),
                property(PlatformConfig.EMAIL_DOMAIN, "Synthetic email domain", "Yeni kullanıcının sentetik e-postasının alanı.",
                        ProviderConfigProperty.STRING_TYPE, "platform.invalid"),
                property(PlatformConfig.LAST_NAME, "Last name", "Yeni kullanıcının soyadı (kullanıcı profili ister).",
                        ProviderConfigProperty.STRING_TYPE, "Player"));
    }

    private static ProviderConfigProperty property(String name, String label, String help, String type, String defaultValue) {
        ProviderConfigProperty p = new ProviderConfigProperty();
        p.setName(name);
        p.setLabel(label);
        p.setHelpText(help);
        p.setType(type);
        p.setDefaultValue(defaultValue);
        if (ProviderConfigProperty.PASSWORD.equals(type)) p.setSecret(true);
        return p;
    }
}
