package com.cantalay.keycloak.platform;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager;

import java.util.Map;

/**
 * Oturum açmış kullanıcının hesabına platform kimliği bağlama (/realms/{realm}/platform-identity/...). Kullanıcı kendi erişim
 * belirteciyle gelir (auth-gateway iletir). Aynı platform kimliği başka hesaba bağlıysa 409: hesaplar birleştirilmez, istemci
 * oyuncuya sorar.
 */
public final class PlatformLinkResource {

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static final class LinkRequest {
        public String platform;
        public String token;
    }

    private static final Logger LOG = Logger.getLogger(PlatformLinkResource.class);
    private final KeycloakSession session;

    PlatformLinkResource(KeycloakSession session) {
        this.session = session;
    }

    @GET
    @Path("links")
    @Produces(MediaType.APPLICATION_JSON)
    public Response links() {
        UserModel user = user();
        if (user == null) return error(Response.Status.UNAUTHORIZED, "unauthorized");
        return Response.ok(Map.of(
                Platforms.GAME_CENTER, user.getFirstAttribute(Platforms.attribute(Platforms.GAME_CENTER)) != null,
                Platforms.PLAY_GAMES, user.getFirstAttribute(Platforms.attribute(Platforms.PLAY_GAMES)) != null)).build();
    }

    @POST
    @Path("link")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response link(LinkRequest request) {
        UserModel user = user();
        if (user == null) return error(Response.Status.UNAUTHORIZED, "unauthorized");
        if (request == null || Platforms.normalize(request.platform) == null || request.token == null || request.token.isBlank())
            return error(Response.Status.BAD_REQUEST, "invalid_request");
        RealmModel realm = session.getContext().getRealm();
        AuthenticatorConfigModel model = realm.getAuthenticatorConfigByAlias(PlatformConfig.ALIAS);
        if (model == null) return error(Response.Status.SERVICE_UNAVAILABLE, "not_configured");
        PlatformIdentity identity;
        try {
            identity = PlatformVerifiers.verify(PlatformConfig.from(model.getConfig(), PlatformSecrets.of(session)), request.platform, request.token);
        } catch (PlatformVerificationException e) {
            LOG.warnf("Platform bağlama reddedildi (%s, realm %s): %s", request.platform, realm.getName(), e.getMessage());
            return error(Response.Status.UNAUTHORIZED, "invalid_platform_token");
        }
        UserModel owner = PlatformUsers.find(session, realm, identity);
        if (owner != null && !owner.getId().equals(user.getId())) return error(Response.Status.CONFLICT, "already_linked");
        PlatformUsers.link(user, identity);
        return Response.ok(Map.of("platform", identity.platform(), "linked", true)).build();
    }

    @DELETE
    @Path("link/{platform}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response unlink(@PathParam("platform") String platform) {
        UserModel user = user();
        if (user == null) return error(Response.Status.UNAUTHORIZED, "unauthorized");
        String p = Platforms.normalize(platform);
        if (p == null) return error(Response.Status.BAD_REQUEST, "invalid_request");
        PlatformUsers.unlink(user, p);
        return Response.ok(Map.of("platform", p, "linked", false)).build();
    }

    private UserModel user() {
        AuthenticationManager.AuthResult auth = new AppAuthManager.BearerTokenAuthenticator(session).authenticate();
        return auth == null ? null : auth.user();
    }

    private static Response error(Response.Status status, String code) {
        return Response.status(status).type(MediaType.APPLICATION_JSON).entity(Map.of("error", code)).build();
    }
}
