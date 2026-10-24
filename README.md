# talay-keycloak-providers

Talay platformunun Keycloak eklentileri. Keycloak sürümüyle aynı tutulur (`pom.xml` → `keycloak.version`, şu an 26.7.3).

## platform-identity: Game Center ve Play Games ile giriş

İlk kullanıcı Colony Conquest'tir (conquorer docs/62 §12). Oyuncu cihazındaki platform hesabıyla (iOS Game Center, Android Play
Games) parola girmeden oturum açar. Platform kimliği Keycloak kullanıcısının özniteliğinde (`platform.gamecenter`,
`platform.playgames`) durur. Böylece kimlik Keycloak'ta kalır, uygulama sunucusu giriş bilgisi tutmaz.

### Girişler

**Direct grant authenticator `platform-identity`.** Akış bu authenticator'a bağlı ayrı bir istemciyle kullanılır
(`<realm>-platform`, `authentication_flow_binding_overrides.direct_grant`). Örnek istek:

```
POST /realms/<realm>/protocol/openid-connect/token
grant_type=password&client_id=<realm>-platform&platform=gamecenter|playgames&platform_token=…&scope=openid offline_access
```

- `gamecenter`: `platform_token`, `GKLocalPlayer.fetchItemsForIdentityVerificationSignature` çıktısının JSON'udur (düz ya da
  base64url).
  - Alanlar: `publicKeyUrl`, `signature`, `salt`, `timestamp`, `teamPlayerId`, `bundleId`, `displayName`.
  - Doğrulanan veri: `teamPlayerID + bundleID + timestamp (8 bayt, büyük uçlu) + salt`, SHA256withRSA.
  - Sertifika yalnız HTTPS'te ve izinli alan adlarında olabilir (varsayılan `apple.com`), geçerli ve `O=Apple Inc.` olmalıdır.
  - İmza en çok `gameCenterMaxAgeSeconds` (900) yaşında olabilir.
- `playgames`: `platform_token`, `GamesSignInClient.requestServerSideAccess(webClientId)` kodudur.
  - Kod Google token ucunda değiştirilir, Games API `players/me` uçundan `playerId` okunur.
  - Kod tek kullanımlıktır.
- **Kullanıcı:** bağlı kullanıcı yoksa ve `createUsers` açıksa yeni kullanıcı açılır. Kullanıcı adı `gc-…` ya da `pg-…`; e-posta
  sentetik ve doğrulanmış (`emailDomain`); soyad `lastName`. Bildirimsel kullanıcı profilinin istediği alanlar dolar.
- **Hata:** istemciye yalnız `invalid_grant` gider, ayrıntı Keycloak günlüğündedir.

**Hesap bağlama: `/realms/<realm>/platform-identity/…`.** Kullanıcının kendi erişim belirteciyle çağrılır.

| Uç | Ne yapar |
|---|---|
| `POST link` `{"platform","token"}` | Platform kimliğini bu hesaba bağlar. Kimlik başka hesaba bağlıysa `409 already_linked` (hesaplar birleştirilmez). |
| `DELETE link/{platform}` | Bağı kaldırır. |
| `GET links` | `{"gamecenter": bool, "playgames": bool}` |

Ayarlar `platform-identity` adlı authenticator yapılandırmasındadır (Terraform yazar):

| Ayar | Anlamı |
|---|---|
| `gameCenterBundleIds` | izinli iOS paket kimlikleri; boşsa Game Center kapalı |
| `gameCenterKeyHosts` | sertifika alan adları (`apple.com`) |
| `gameCenterMaxAgeSeconds` | imza yaşı (900) |
| `playGamesClientId`, `playGamesClientSecret` | Google OAuth web istemcisi; boşsa Play Games kapalı |
| `playGamesTokenUrl`, `playGamesPlayerUrl` | Google uçları (varsayılanlar) |
| `createUsers`, `emailDomain`, `lastName` | yeni kullanıcı |

## Dağıtım

- **İmaj:** CI, `ghcr.io/cantalay/talay-keycloak-providers:sha-<7>` imajını üretir. Bu küçük bir busybox imajıdır, JAR'ı
  `/target/` altına kopyalar.
- **Keycloak'a yükleme:** talay-identity bu imajı keycloakx `extraInitContainers` ile çalıştırır. JAR `/opt/keycloak/providers`
  birimine gelir; `kc.sh start` açılışta derlemeyi kendisi yapar.

## Geliştirme

```bash
./mvnw verify
```

Testler Game Center imzasını testte üretilen anahtarla (JDK keytool), Play Games'i sahte Google sunucusuyla sınar. Gerçek
Keycloak'ta denemek için:

```bash
docker run --network host \
  -v $PWD/target/talay-keycloak-providers.jar:/opt/keycloak/providers/p.jar:ro \
  quay.io/keycloak/keycloak:26.7.3 start-dev
```
