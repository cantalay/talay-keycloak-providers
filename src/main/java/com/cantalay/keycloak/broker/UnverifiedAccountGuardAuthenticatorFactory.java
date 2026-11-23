package com.cantalay.keycloak.broker;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.List;

/** {@code idp-unverified-account-guard}: sosyal girişten sonra parolalı + onaysız hesaba oturum açtırmaz. */
public final class UnverifiedAccountGuardAuthenticatorFactory implements AuthenticatorFactory {

    public static final String PROVIDER_ID = "idp-unverified-account-guard";
    private static final UnverifiedAccountGuardAuthenticator SINGLETON = new UnverifiedAccountGuardAuthenticator();
    private static final AuthenticationExecutionModel.Requirement[] REQUIREMENTS = {
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
        return "Refuse social sign-in into an unverified password account";
    }

    @Override
    public String getReferenceCategory() {
        return "brokerGuard";
    }

    @Override
    public String getHelpText() {
        return "Post broker login: parolası olan ve e-postası onaylanmamış hesaba sosyal girişle oturum açtırmaz; "
                + "istemciye error_description=account_exists_unverified ile döner.";
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
