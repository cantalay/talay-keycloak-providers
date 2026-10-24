package com.cantalay.keycloak.platform;

import java.io.FileInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Testte üretilen kendinden imzalı anahtar çiftleri (JDK keytool; depoda özel anahtar tutulmaz). Yalnız test.
 */
final class TestKeys {
    record Pair(PrivateKey key, X509Certificate certificate) {
    }

    private TestKeys() {
    }

    static Pair generate(String dname) throws Exception {
        Path dir = Files.createTempDirectory("platform-keys");
        Path store = dir.resolve("k.p12");
        String keytool = Path.of(System.getProperty("java.home"), "bin", "keytool").toString();
        Process p = new ProcessBuilder(List.of(keytool, "-genkeypair", "-alias", "k", "-keyalg", "RSA", "-keysize", "2048",
                "-sigalg", "SHA256withRSA", "-validity", "30", "-dname", dname, "-storetype", "PKCS12",
                "-keystore", store.toString(), "-storepass", "test-only", "-keypass", "test-only"))
                .redirectErrorStream(true).start();
        String out = new String(p.getInputStream().readAllBytes());
        if (p.waitFor() != 0) throw new IllegalStateException("keytool: " + out);
        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (FileInputStream in = new FileInputStream(store.toFile())) {
            ks.load(in, "test-only".toCharArray());
        }
        return new Pair((PrivateKey) ks.getKey("k", "test-only".toCharArray()), (X509Certificate) ks.getCertificate("k"));
    }
}
