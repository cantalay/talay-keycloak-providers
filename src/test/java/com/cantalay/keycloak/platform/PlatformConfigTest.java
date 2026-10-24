package com.cantalay.keycloak.platform;

import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class PlatformConfigTest {
    @Test
    void defaultsAndParsing() {
        PlatformConfig empty = PlatformConfig.from(null);
        assertThat(empty.gameCenterEnabled()).isFalse();
        assertThat(empty.playGamesEnabled()).isFalse();
        assertThat(empty.gameCenterKeyHosts()).containsExactly("apple.com");
        assertThat(empty.gameCenterMaxAge().toSeconds()).isEqualTo(900);
        assertThat(empty.createUsers()).isTrue();
        assertThat(empty.playGamesTokenUrl()).isEqualTo(PlatformConfig.DEFAULT_TOKEN_URL);

        PlatformConfig c = PlatformConfig.from(Map.of(PlatformConfig.BUNDLE_IDS, " a.b , c.d ,", PlatformConfig.MAX_AGE, "60",
                PlatformConfig.CREATE_USERS, "false", PlatformConfig.PG_CLIENT_ID, "id", PlatformConfig.PG_CLIENT_SECRET, "s"));
        assertThat(c.gameCenterBundleIds()).containsExactlyInAnyOrder("a.b", "c.d");
        assertThat(c.gameCenterMaxAge().toSeconds()).isEqualTo(60);
        assertThat(c.createUsers()).isFalse();
        assertThat(c.playGamesEnabled()).isTrue();
        assertThat(Platforms.normalize(" GameCenter ")).isEqualTo("gamecenter");
        assertThat(Platforms.normalize("steam")).isNull();
        assertThat(Platforms.attribute("playgames")).isEqualTo("platform.playgames");
    }
}
