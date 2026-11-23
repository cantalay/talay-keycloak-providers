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
| `playGamesClientId`, `playGamesClientSecret` | Google OAuth web istemcisi; boşsa Play Games kapalı. Sır `${vault.<anahtar>}` referansı olarak yazılır: Keycloak kasası (`KC_VAULT=file`) dosyadan okur, sır Terraform durumuna düşmez |
| `playGamesTokenUrl`, `playGamesPlayerUrl` | Google uçları (varsayılanlar) |
| `createUsers`, `emailDomain`, `lastName` | yeni kullanıcı |

## Sosyal giriş bağlama koruması (Google / Apple)

Keycloak'ın `idp-auto-link`'i ilk sosyal girişte aynı e-postalı hesaba **hiç doğrulamadan** bağlar. E-posta onayı zorunlu
olmayan realm'lerde bu önceden hesap ele geçirmedir: saldırgan kurbanın adresiyle parolalı kayıt olur (onaysız), kurban
sonra Google ile girince Keycloak Google'ı saldırganın parolasını bildiği hesaba bağlar. İki authenticator bunu kapatır
(talay-identity `social.tf` kurar):

| Authenticator | Akış | Ne yapar |
|---|---|---|
| `idp-auto-link-verified-only` | ilk giriş (`social-first-login`), `idp-create-user-if-unique` ile ALTERNATIVE | Aynı e-postalı hesaba yalnız şu üçü tutarsa bağlar: hesabın e-postası onaylı, sağlayıcının e-postası aynı (büyük/küçük harf duyarsız), sağlayıcı e-postaya kefil (`trustEmail` açık ve belirteçte `email_verified=false` yok). |
| `idp-unverified-account-guard` | giriş sonrası (`social-post-login`, kimlik sağlayıcının `postBrokerLoginFlowAlias`'ı), REQUIRED | Her sosyal girişte (bağ eskiden kurulmuş olsa da) parolası olan ve e-postası onaylanmamış hesaba oturum açtırmaz. Parolasız hesaplar etkilenmez. |

**Ret:** Keycloak sayfası gösterilmez. Tarayıcı istemcinin dönüş adresine OAuth hata yanıtıyla gider (Keycloak'ın
"vazgeç" yolu): `<redirect_uri>?error=access_denied&error_description=<neden>&state=…&iss=…`, kod yoktur.

| `error_description` | Anlamı |
|---|---|
| `account_exists_unverified` | Bu e-postayla açılmış, e-postası onaylanmamış (parolalı) bir hesap var. Çıkış yolu parola sıfırlama (adres sahipliğini kanıtlar, bilinmeyen parolayı değiştirir, eski oturumları kapatır); onay e-postası değil. |
| `account_exists` | Hesap var ama bu sağlayıcı kimliği ona bağlanamaz: sağlayıcı e-postayı doğrulamadı ya da yalnız kullanıcı adı çakıştı. |

Reddedilen girişte kullanıcı oluşturulmaz, bağ kurulmaz, kullanıcı oturumu ve SSO çerezi oluşmaz. auth-gateway
`/social` bu iki nedeni `{error, errorDescription}` gövdesiyle alıp 409 `account_exists_unverified` / `account_exists`
döner. Olay günlüğünde `federated_identity_account_exists`, ayrıntı `reason`.

## Dağıtım

- **İmaj:** CI, `ghcr.io/cantalay/talay-keycloak-providers:sha-<7>` imajını üretir. Bu küçük bir busybox imajıdır, JAR'ı
  `/target/` altına kopyalar.
- **Keycloak'a yükleme:** talay-identity bu imajı keycloakx `extraInitContainers` ile çalıştırır. JAR `/opt/keycloak/providers`
  birimine gelir; `kc.sh start` açılışta derlemeyi kendisi yapar.

## Geliştirme

```bash
./mvnw verify
```

Testler Game Center imzasını testte üretilen anahtarla (JDK keytool), Play Games'i sahte Google sunucusuyla sınar.
`SocialLinkIT` (failsafe, Docker gerekir; yoksa atlanır) paketlenmiş JAR'ı gerçek Keycloak 26.7.3 kapsayıcısına yükler,
ikinci bir realm'i Google yerine kimlik sağlayıcısı yapar ve tarayıcı akışını HTTP istemcisiyle sürer. Gerçek
Keycloak'ta denemek için:

```bash
docker run --network host \
  -v $PWD/target/talay-keycloak-providers.jar:/opt/keycloak/providers/p.jar:ro \
  quay.io/keycloak/keycloak:26.7.3 start-dev
```
