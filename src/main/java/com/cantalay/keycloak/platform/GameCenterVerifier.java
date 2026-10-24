package com.cantalay.keycloak.platform;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import org.keycloak.util.JsonSerialization;

import java.io.ByteArrayInputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Game Center kimlik doğrulama imzası (GKLocalPlayer.fetchItemsForIdentityVerificationSignature). İmzalanan veri:
 * teamPlayerID (UTF-8) + bundleID (UTF-8) + zaman damgası (8 bayt, büyük uçlu, ms) + tuz. Genel anahtar Apple'ın HTTPS
 * adresindeki sertifikadadır; adres yalnız izinli alan adlarından (varsayılan apple.com) kabul edilir, sertifika geçerli ve
 * Apple adına olmalıdır. Zaman damgası {@link PlatformConfig#gameCenterMaxAge()} içinde olmalı (yeniden oynatmaya karşı).
 */
public final class GameCenterVerifier {

    /** İstemcinin gönderdiği paket (JSON; düz ya da base64url). */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static final class Payload {
        public String publicKeyUrl;
        public String signature;
        public String salt;
        public long timestamp;
        public String teamPlayerId;
        public String bundleId;
        public String displayName;
    }

    /** Sertifika kaynağı (testte sahte). */
    public interface CertificateSource {
        X509Certificate fetch(URI uri) throws Exception;
    }

    private static final Duration CACHE = Duration.ofHours(12);
    private static final Map<URI, Cached> CERTS = new ConcurrentHashMap<>();

    private record Cached(X509Certificate certificate, Instant fetchedAt) {
    }

    private final PlatformConfig config;
    private final Clock clock;
    private final CertificateSource certificates;
    private final boolean requireAppleSubject;

    public GameCenterVerifier(PlatformConfig config) {
        this(config, Clock.systemUTC(), GameCenterVerifier::download, true);
    }

    GameCenterVerifier(PlatformConfig config, Clock clock, CertificateSource certificates, boolean requireAppleSubject) {
        this.config = config;
        this.clock = clock;
        this.certificates = certificates;
        this.requireAppleSubject = requireAppleSubject;
    }

    public PlatformIdentity verify(String token) throws PlatformVerificationException {
        if (!config.gameCenterEnabled()) throw new PlatformVerificationException("Game Center kapalı (paket kimliği yok)");
        Payload p = parse(token);
        if (blank(p.publicKeyUrl) || blank(p.signature) || blank(p.salt) || blank(p.teamPlayerId) || blank(p.bundleId) || p.timestamp <= 0)
            throw new PlatformVerificationException("eksik alan");
        if (!config.gameCenterBundleIds().contains(p.bundleId))
            throw new PlatformVerificationException("paket kimliği izinli değil: " + p.bundleId);
        Instant signedAt = Instant.ofEpochMilli(p.timestamp);
        Duration age = Duration.between(signedAt, clock.instant()).abs();
        if (age.compareTo(config.gameCenterMaxAge()) > 0)
            throw new PlatformVerificationException("imza zamanı aşıldı: " + age.toSeconds() + " sn");

        URI uri = keyUri(p.publicKeyUrl);
        X509Certificate certificate = certificate(uri);
        try {
            certificate.checkValidity(Date.from(clock.instant()));
        } catch (Exception e) {
            throw new PlatformVerificationException("sertifika geçerli değil", e);
        }
        if (requireAppleSubject && !certificate.getSubjectX500Principal().getName().contains("O=Apple Inc."))
            throw new PlatformVerificationException("sertifika Apple'ın değil");

        byte[] salt = decode(p.salt, "tuz");
        byte[] signature = decode(p.signature, "imza");
        byte[] player = p.teamPlayerId.getBytes(StandardCharsets.UTF_8);
        byte[] bundle = p.bundleId.getBytes(StandardCharsets.UTF_8);
        ByteBuffer data = ByteBuffer.allocate(player.length + bundle.length + 8 + salt.length);
        data.put(player).put(bundle).putLong(p.timestamp).put(salt);
        try {
            Signature verifier = Signature.getInstance("SHA256withRSA");
            verifier.initVerify(certificate.getPublicKey());
            verifier.update(data.array());
            if (!verifier.verify(signature)) throw new PlatformVerificationException("imza tutmuyor");
        } catch (PlatformVerificationException e) {
            throw e;
        } catch (Exception e) {
            throw new PlatformVerificationException("imza doğrulanamadı", e);
        }
        return new PlatformIdentity(Platforms.GAME_CENTER, p.teamPlayerId, p.displayName == null ? "" : p.displayName);
    }

    /** Adres HTTPS ve izinli alan adında (ör. static.gc.apple.com) olmalı. */
    URI keyUri(String url) throws PlatformVerificationException {
        URI uri;
        try {
            uri = URI.create(url);
        } catch (IllegalArgumentException e) {
            throw new PlatformVerificationException("anahtar adresi geçersiz", e);
        }
        String host = uri.getHost() == null ? "" : uri.getHost().toLowerCase(Locale.ROOT);
        if (!"https".equalsIgnoreCase(uri.getScheme()) || uri.getUserInfo() != null || (uri.getPort() != -1 && uri.getPort() != 443))
            throw new PlatformVerificationException("anahtar adresi HTTPS değil: " + url);
        List<String> hosts = config.gameCenterKeyHosts();
        boolean allowed = hosts.stream().anyMatch(h -> host.equals(h) || host.endsWith("." + h));
        if (!allowed) throw new PlatformVerificationException("anahtar adresi izinli alanda değil: " + host);
        return uri;
    }

    private X509Certificate certificate(URI uri) throws PlatformVerificationException {
        Cached cached = CERTS.get(uri);
        if (cached != null && cached.fetchedAt().plus(CACHE).isAfter(clock.instant())) return cached.certificate();
        try {
            X509Certificate certificate = certificates.fetch(uri);
            CERTS.put(uri, new Cached(certificate, clock.instant()));
            return certificate;
        } catch (Exception e) {
            throw new PlatformVerificationException("sertifika alınamadı: " + uri, e);
        }
    }

    static void clearCache() {
        CERTS.clear();
    }

    private static X509Certificate download(URI uri) throws Exception {
        HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).followRedirects(HttpClient.Redirect.NEVER).build();
        HttpResponse<byte[]> response = client.send(HttpRequest.newBuilder(uri).timeout(Duration.ofSeconds(10)).GET().build(),
                HttpResponse.BodyHandlers.ofByteArray());
        if (response.statusCode() != 200) throw new IllegalStateException("HTTP " + response.statusCode());
        return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(response.body()));
    }

    static Payload parse(String token) throws PlatformVerificationException {
        if (blank(token) || token.length() > 16_384) throw new PlatformVerificationException("belirteç boş ya da çok uzun");
        String json = token.trim();
        if (!json.startsWith("{")) {
            try {
                json = new String(Base64.getUrlDecoder().decode(json), StandardCharsets.UTF_8);
            } catch (IllegalArgumentException e) {
                throw new PlatformVerificationException("belirteç base64url değil", e);
            }
        }
        try {
            return JsonSerialization.readValue(json, Payload.class);
        } catch (Exception e) {
            throw new PlatformVerificationException("belirteç JSON değil", e);
        }
    }

    private static byte[] decode(String value, String what) throws PlatformVerificationException {
        try {
            return Base64.getDecoder().decode(value);
        } catch (IllegalArgumentException e) {
            throw new PlatformVerificationException(what + " base64 değil", e);
        }
    }

    private static boolean blank(String s) {
        return s == null || s.isBlank();
    }

    /** Desteklenen paket kimlikleri (test). */
    Set<String> bundleIds() {
        return config.gameCenterBundleIds();
    }
}
