package com.cantalay.keycloak.broker;

import org.junit.jupiter.api.Test;

import java.util.Locale;

import static org.assertj.core.api.Assertions.assertThat;

class VerifiedOnlyAutoLinkAuthenticatorTest {

    @Test
    void emailComparisonIgnoresCaseIndependentOfTheLocale() {
        Locale previous = Locale.getDefault();
        Locale.setDefault(Locale.forLanguageTag("tr-TR")); // "I".toLowerCase() → "ı" olurdu
        try {
            assertThat(VerifiedOnlyAutoLinkAuthenticator.sameEmail("isil@ornek.com", "ISIL@Ornek.COM")).isTrue();
            assertThat(VerifiedOnlyAutoLinkAuthenticator.sameEmail(" can@ornek.com", "can@ornek.com ")).isTrue();
            assertThat(VerifiedOnlyAutoLinkAuthenticator.sameEmail("can@ornek.com", "can@ornek.co")).isFalse();
            assertThat(VerifiedOnlyAutoLinkAuthenticator.sameEmail(null, "can@ornek.com")).isFalse();
            assertThat(VerifiedOnlyAutoLinkAuthenticator.sameEmail("can@ornek.com", " ")).isFalse();
        } finally {
            Locale.setDefault(previous);
        }
    }
}
