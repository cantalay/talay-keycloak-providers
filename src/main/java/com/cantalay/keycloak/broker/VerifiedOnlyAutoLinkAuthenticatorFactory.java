package com.cantalay.keycloak.broker;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.List;

/** {@code idp-auto-link-verified-only}: ilk sosyal girişte yalnız onaylı, aynı e-postalı hesaba bağlar. */
public final class VerifiedOnlyAutoLinkAuthenticatorFactory implements AuthenticatorFactory {

    public static final String PROVIDER_ID = "idp-auto-link-verified-only";
    private static final VerifiedOnlyAutoLinkAuthenticator SINGLETON = new VerifiedOnlyAutoLinkAuthenticator();
    private static final AuthenticationExecutionModel.Requirement[] REQUIREMENTS = {
            AuthenticationExecutionModel.Requirement.ALTERNATIVE,
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.DISABLED,
    };

    @Override
    public Authenticator create(KeycloakSession session) {
        return SINGLETON;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "Automatically link existing user with a verified email";
    }

    @Override
    public String getReferenceCategory() {
        return "autoLink";
    }

    @Override
    public String getHelpText() {
        return "Aynı e-postalı mevcut hesaba yalnız e-postası onaylıysa ve sağlayıcı e-postaya kefilse bağlar; değilse bağlamadan "
                + "istemciye error_description=account_exists_unverified (ya da account_exists) ile döner.";
    }

    @Override
    public boolean isConfigurable() {
        return false;
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
    public List<ProviderConfigProperty> getConfigProperties() {
        return List.of();
    }

    @Override
    public void init(Config.Scope config) {
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public void close() {
    }
}
