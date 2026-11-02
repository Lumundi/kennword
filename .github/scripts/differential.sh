#!/usr/bin/env bash
#
# Starts Vaultwarden and this implementation side by side, each with a data
# folder of its own and the same (dummy) web vault, and runs the Differential
# test suite against both.
#
# Usage: differential.sh <vaultwarden binary> [phpunit arguments...]
# Ports 8000-8004 (Vaultwarden), 8080-8084 (PHP), 8090 (our notifications daemon), 2501-2502
# (SMTP sinks) and 2503 (fake Yubico, Duo, OpenID and push relay services) must be free.
# Ports 80 and 443 serve fake websites for the icon tests, where they can be bound.
# With KEYCLOAK_URL, a Keycloak that imported keycloak-realm.json (reference.yml starts one), a sixth
# pair logs in there, on ports 8005 (Vaultwarden) and 8085 (PHP).

set -euo pipefail

binary="$(realpath "$1")"
shift
work="$(mktemp -d)"
mkdir -p "${work}/reference" "${work}/subject" "${work}/shared" "${work}/features-reference" "${work}/features-subject" \
    "${work}/mail-reference" "${work}/mail-subject" "${work}/sso-reference" "${work}/sso-subject" "${work}/web-vault/app" "${work}/web-vault/images"
# A few files for tests/Differential/WebVaultTest, without a version file.
echo '<!DOCTYPE html><title>Web vault</title>' > "${work}/web-vault/index.html"
echo 'console.log("web vault");' > "${work}/web-vault/app/main.js"
echo 'body{margin:0}' > "${work}/web-vault/app/STYLE.CSS"
echo 'data' > "${work}/web-vault/app/data.unknown"
echo '<svg xmlns="http://www.w3.org/2000/svg"/>' > "${work}/web-vault/images/icon.svg"
echo '<!DOCTYPE html><title>Connector</title>' > "${work}/web-vault/webauthn-connector.html"
echo 'secret' > "${work}/web-vault/.hidden"
export WEB_VAULT_FOLDER="${work}/web-vault/"
# Every flow logs in; Vaultwarden's limits (10 logins, then one a minute) would cut the suite short.
export LOGIN_RATELIMIT_MAX_BURST=10000 UNAUTHENTICATED_RATELIMIT_MAX_BURST=10000 ADMIN_RATELIMIT_MAX_BURST=10000
# The admin panel: a plain token on the default pair, an Argon2id PHC string of another one
# on the mail pair (tests/Differential/AdminTest). The pair with groups and events has none.
admin_token=differential-admin-token
mail_admin_token='$argon2id$v=19$m=19456,t=2,p=1$1u9NMozy1wIOfBlcUShBoA$QV3xAUsbGY31IC8a82I+DXWOcb6PBY7xD3/yupWvJ3k'

pids=()
trap 'kill "${pids[@]}" 2> /dev/null || true' EXIT

# One RSA key for both: unknown emails get KDF settings derived from it.
DATA_FOLDER="${work}/subject" php artisan parity:token encode admin key --no-ansi > /dev/null
cp "${work}/subject/rsa_key.pem" "${work}/reference/rsa_key.pem"
cp "${work}/subject/rsa_key.pem" "${work}/shared/rsa_key.pem"
cp "${work}/subject/rsa_key.pem" "${work}/features-reference/rsa_key.pem"
cp "${work}/subject/rsa_key.pem" "${work}/features-subject/rsa_key.pem"
cp "${work}/subject/rsa_key.pem" "${work}/mail-reference/rsa_key.pem"
cp "${work}/subject/rsa_key.pem" "${work}/mail-subject/rsa_key.pem"
cp "${work}/subject/rsa_key.pem" "${work}/sso-reference/rsa_key.pem"
cp "${work}/subject/rsa_key.pem" "${work}/sso-subject/rsa_key.pem"

DATA_FOLDER="${work}/reference" ADMIN_TOKEN="${admin_token}" ROCKET_PORT=8000 "${binary}" > "${work}/reference.log" 2>&1 &
pids+=($!)
# A second pair on one database: Vaultwarden creates it, we use it too.
DATA_FOLDER="${work}/shared" ROCKET_PORT=8001 "${binary}" > "${work}/shared-reference.log" 2>&1 &
pids+=($!)
# A third pair with the optional features groups and events, which change what the clients see,
# and YubiKey and Duo two-factor login against fake services over HTTPS. Their certificate
# authority is the only one these servers trust.
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj '/CN=Differential CA' -addext 'basicConstraints=critical,CA:TRUE' \
    -addext 'keyUsage=critical,keyCertSign' -keyout "${work}/ca.key" -out "${work}/ca.pem" 2> /dev/null
openssl req -newkey rsa:2048 -nodes -subj '/CN=127.0.0.1' -keyout "${work}/services.key" -out "${work}/services.csr" 2> /dev/null
printf 'subjectAltName=IP:127.0.0.1\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n' \
    > "${work}/services.ext"
openssl x509 -req -in "${work}/services.csr" -CA "${work}/ca.pem" -CAkey "${work}/ca.key" -CAcreateserial -days 2 \
    -extfile "${work}/services.ext" -out "${work}/services.pem" 2> /dev/null
duo_ikey=DIDIFFERENTIALGLOBAL
features_env=(ORG_GROUPS_ENABLED=true ORG_EVENTS_ENABLED=true SSL_CERT_FILE="${work}/ca.pem" HTTP_REQUEST_BLOCK_NON_GLOBAL_IPS=false
    YUBICO_CLIENT_ID=1 YUBICO_SECRET_KEY=MDEyMzQ1Njc4OWFiY2RlZmdoaWo= YUBICO_SERVER=https://127.0.0.1:2503/wsapi/2.0/verify
    DUO_IKEY="${duo_ikey}" DUO_SKEY="$(php -r "echo substr(hash('sha256', 'duo:${duo_ikey}'), 0, 40);")" DUO_HOST=127.0.0.1:2503)
# The icon service of this pair fetches the fake websites below (tests/Differential/IconsTest): hosts
# starting with "blocked." are blocked, and slow icons give up after three seconds.
features_env+=('HTTP_REQUEST_BLOCK_REGEX=^blocked\.' ICON_DOWNLOAD_TIMEOUT=3)
# Websites with icons on ports 80 and 443, under names that resolve to 127.0.0.1 (.localhost, and
# /etc/hosts in CI). Their certificate leaves out httponly.icons.localhost, whose HTTPS fails.
openssl req -newkey rsa:2048 -nodes -subj '/CN=icons.localhost' -keyout "${work}/websites.key" -out "${work}/websites.csr" 2> /dev/null
printf 'subjectAltName=IP:127.0.0.1,%s\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n' \
    "$(php .github/scripts/fake-websites.php --names | grep -v '^httponly\.' | sed 's/^/DNS:/' | paste -sd, -)" > "${work}/websites.ext"
openssl x509 -req -in "${work}/websites.csr" -CA "${work}/ca.pem" -CAkey "${work}/ca.key" -CAcreateserial -days 2 \
    -extfile "${work}/websites.ext" -out "${work}/websites.pem" 2> /dev/null
php .github/scripts/fake-websites.php "${work}/websites.pem" "${work}/websites.key" "${work}/websites-state" > "${work}/websites.log" 2>&1 &
pids+=($!)
sso_secret=differential-sso-secret
env YUBICO_SECRET_KEY=MDEyMzQ1Njc4OWFiY2RlZmdoaWo= SSO_CLIENT_SECRET="${sso_secret}" php .github/scripts/fake-services.php 2503 \
    "${work}/services.pem" "${work}/services.key" "${work}/services-state" > "${work}/services.log" 2>&1 &
pids+=($!)
# The pair also pushes to mobile devices, each server to a fake relay of its own.
push_installation=2c4d6e8f-1a3b-4c5d-8e9f-0a1b2c3d4e5f
features_env+=(PUSH_ENABLED=true PUSH_INSTALLATION_ID="${push_installation}"
    PUSH_INSTALLATION_KEY="$(php -r "echo substr(hash('sha256', 'relay:${push_installation}'), 0, 20);")")
push_env() {
    echo "PUSH_RELAY_URI=https://127.0.0.1:2503/relay/$1" "PUSH_IDENTITY_URI=https://127.0.0.1:2503/relay/$1/identity"
}
# shellcheck disable=SC2046
env DATA_FOLDER="${work}/features-reference" "${features_env[@]}" $(push_env features-reference) ROCKET_PORT=8002 "${binary}" > "${work}/features-reference.log" 2>&1 &
pids+=($!)
# A fourth pair sends mail, each server to an SMTP sink of its own that keeps the messages.
php .github/scripts/smtp-sink.php 2501 "${work}/mail-reference-inbox" > "${work}/sink-reference.log" 2>&1 &
pids+=($!)
php .github/scripts/smtp-sink.php 2502 "${work}/mail-subject-inbox" > "${work}/sink-subject.log" 2>&1 &
pids+=($!)
mail_env=(SMTP_HOST=127.0.0.1 SMTP_SECURITY=off SMTP_FROM=vaultwarden@example.com SMTP_TIMEOUT=5
    EMAIL_2FA_ENFORCE_ON_VERIFIED_INVITE=true EMAIL_2FA_AUTO_FALLBACK=true ADMIN_TOKEN="${mail_admin_token}")
env DATA_FOLDER="${work}/mail-reference" "${mail_env[@]}" SMTP_PORT=2501 ROCKET_PORT=8003 "${binary}" > "${work}/mail-reference.log" 2>&1 &
pids+=($!)
# A fifth pair logs in with SSO at the fake OpenID provider (tests/Differential/SsoTest).
sso_env=(SSO_ENABLED=true SSO_AUTHORITY=https://127.0.0.1:2503/oidc SSO_CLIENT_ID=vaultwarden SSO_CLIENT_SECRET="${sso_secret}"
    SSO_SCOPES="email profile offline_access" SSL_CERT_FILE="${work}/ca.pem")
# This pair sends icons to an external service of its own (tests/Differential/IconsTest).
sso_env+=('ICON_SERVICE=https://icons.example.net/{}/icon.png?size=32' ICON_REDIRECT_CODE=308)
env DATA_FOLDER="${work}/sso-reference" "${sso_env[@]}" ROCKET_PORT=8004 "${binary}" > "${work}/sso-reference.log" 2>&1 &
pids+=($!)

# php -S rather than artisan serve, which drops most environment variables.
# Laravel's router script expects to run in the public folder.
export DATA_FOLDER="${work}/subject"
php artisan kennword:migrate --no-ansi > /dev/null
DATA_FOLDER="${work}/features-subject" php artisan kennword:migrate --no-ansi > /dev/null
DATA_FOLDER="${work}/mail-subject" php artisan kennword:migrate --no-ansi > /dev/null
DATA_FOLDER="${work}/sso-subject" php artisan kennword:migrate --no-ansi > /dev/null
# Each PHP server has a cache of its own: the rate limits are per server, like Vaultwarden's.
(cd public && ADMIN_TOKEN="${admin_token}" CACHE_PATH="${work}/subject-cache" exec php -d upload_max_filesize=525M -d post_max_size=0 -S 127.0.0.1:8080 ../vendor/laravel/framework/src/Illuminate/Foundation/resources/server.php) \
    > "${work}/subject.log" 2>&1 &
pids+=($!)
(cd public && DATA_FOLDER="${work}/shared" CACHE_PATH="${work}/shared-cache" exec php -d upload_max_filesize=525M -d post_max_size=0 -S 127.0.0.1:8081 ../vendor/laravel/framework/src/Illuminate/Foundation/resources/server.php) \
    > "${work}/shared-subject.log" 2>&1 &
pids+=($!)
# shellcheck disable=SC2046
(cd public && exec env DATA_FOLDER="${work}/features-subject" "${features_env[@]}" $(push_env features-subject) CACHE_PATH="${work}/features-cache" \
    php -d upload_max_filesize=525M -d post_max_size=0 -S 127.0.0.1:8082 ../vendor/laravel/framework/src/Illuminate/Foundation/resources/server.php) \
    > "${work}/features-subject.log" 2>&1 &
pids+=($!)
(cd public && exec env DATA_FOLDER="${work}/mail-subject" "${mail_env[@]}" SMTP_PORT=2502 CACHE_PATH="${work}/mail-cache" \
    php -d upload_max_filesize=525M -d post_max_size=0 -S 127.0.0.1:8083 ../vendor/laravel/framework/src/Illuminate/Foundation/resources/server.php) \
    > "${work}/mail-subject.log" 2>&1 &
pids+=($!)
(cd public && exec env DATA_FOLDER="${work}/sso-subject" "${sso_env[@]}" CACHE_PATH="${work}/sso-cache" \
    php -d upload_max_filesize=525M -d post_max_size=0 -S 127.0.0.1:8084 ../vendor/laravel/framework/src/Illuminate/Foundation/resources/server.php) \
    > "${work}/sso-subject.log" 2>&1 &
pids+=($!)

# The hubs of the default pair: Vaultwarden serves them itself, we from the notifications daemon,
# which the requests of the PHP server reach through a socket in its data folder.
DATA_FOLDER="${work}/subject" php artisan kennword:notifications --listen=127.0.0.1:8090 --no-ansi > "${work}/notifications.log" 2>&1 &
pids+=($!)

for attempt in $(seq 30); do
    curl -sS --cacert "${work}/ca.pem" -o /dev/null https://127.0.0.1:2503/ 2> /dev/null && break
    sleep 0.5
done
for attempt in $(seq 30); do
    # Any answer will do; requests that are no upgrade get the 404 page.
    curl -sS -o /dev/null http://127.0.0.1:8090/notifications/hub 2> /dev/null && break
    if [[ "${attempt}" == 30 ]]; then
        cat "${work}/notifications.log"
        echo "::error::The notifications daemon did not answer."
        exit 1
    fi
    sleep 0.5
done
for url in http://127.0.0.1:{8000,8001,8002,8003,8004,8080,8081,8082,8083,8084}/alive; do
    for attempt in $(seq 60); do
        curl -fsS "${url}" > /dev/null 2>&1 && break
        if [[ "${attempt}" == 60 ]]; then
            cat "${work}"/*.log
            echo "::error::${url} did not answer."
            exit 1
        fi
        sleep 1
    done
done

# A sixth pair logs in with SSO at a real OpenID provider, Keycloak (tests/Differential/KeycloakTest),
# with the admin panel to change the SSO settings between flows.
if [[ -n "${KEYCLOAK_URL:-}" ]]; then
    mkdir -p "${work}/keycloak-reference" "${work}/keycloak-subject"
    cp "${work}/subject/rsa_key.pem" "${work}/keycloak-reference/rsa_key.pem"
    cp "${work}/subject/rsa_key.pem" "${work}/keycloak-subject/rsa_key.pem"
    keycloak_env=(SSO_ENABLED=true SSO_AUTHORITY="${KEYCLOAK_URL}/realms/vaultwarden" SSO_CLIENT_ID=vaultwarden
        'SSO_CLIENT_SECRET=differential+keycloak/secret=' ADMIN_TOKEN="${admin_token}")
    env DATA_FOLDER="${work}/keycloak-reference" "${keycloak_env[@]}" ROCKET_PORT=8005 "${binary}" > "${work}/keycloak-reference.log" 2>&1 &
    pids+=($!)
    DATA_FOLDER="${work}/keycloak-subject" php artisan kennword:migrate --no-ansi > /dev/null
    (cd public && exec env DATA_FOLDER="${work}/keycloak-subject" "${keycloak_env[@]}" CACHE_PATH="${work}/keycloak-cache" \
        php -d upload_max_filesize=525M -d post_max_size=0 -S 127.0.0.1:8085 ../vendor/laravel/framework/src/Illuminate/Foundation/resources/server.php) \
        > "${work}/keycloak-subject.log" 2>&1 &
    pids+=($!)
    # Keycloak takes a while to start and import the realm.
    for url in "${KEYCLOAK_URL}/realms/vaultwarden/.well-known/openid-configuration" http://127.0.0.1:{8005,8085}/alive; do
        for attempt in $(seq 120); do
            curl -fsS "${url}" > /dev/null 2>&1 && break
            if [[ "${attempt}" == 120 ]]; then
                cat "${work}"/keycloak-*.log
                echo "::error::${url} did not answer."
                exit 1
            fi
            sleep 1
        done
    done
    export VW_KEYCLOAK_URL="${KEYCLOAK_URL}" VW_KEYCLOAK_REFERENCE_URL=http://127.0.0.1:8005 VW_KEYCLOAK_SUBJECT_URL=http://127.0.0.1:8085
fi

# Without ports 80 and 443 (on macOS, say) the tests of the icon service are skipped.
for attempt in $(seq 20); do
    if curl -sS --cacert "${work}/ca.pem" -o /dev/null https://links.icons.localhost/ 2> /dev/null; then
        export VW_WEBSITES_STATE="${work}/websites-state" VW_REFERENCE_ICONS="${work}/reference/icon_cache" \
            VW_SUBJECT_ICONS="${work}/subject/icon_cache" VW_FEATURES_REFERENCE_ICONS="${work}/features-reference/icon_cache" \
            VW_FEATURES_SUBJECT_ICONS="${work}/features-subject/icon_cache"
        break
    fi
    if [[ "${attempt}" == 20 ]]; then
        echo "The fake websites did not answer; the icon tests are skipped."
        cat "${work}/websites.log"
    fi
    sleep 0.5
done
status=0
VW_REFERENCE_URL=http://127.0.0.1:8000 VW_SUBJECT_URL=http://127.0.0.1:8080 VW_SUBJECT_NOTIFICATIONS_URL=http://127.0.0.1:8090 \
    VW_SHARED_REFERENCE_URL=http://127.0.0.1:8001 VW_SHARED_SUBJECT_URL=http://127.0.0.1:8081 \
    VW_FEATURES_REFERENCE_URL=http://127.0.0.1:8002 VW_FEATURES_SUBJECT_URL=http://127.0.0.1:8082 \
    VW_MAIL_REFERENCE_URL=http://127.0.0.1:8003 VW_MAIL_SUBJECT_URL=http://127.0.0.1:8083 \
    VW_MAIL_REFERENCE_DIR="${work}/mail-reference-inbox" VW_MAIL_SUBJECT_DIR="${work}/mail-subject-inbox" \
    VW_SSO_REFERENCE_URL=http://127.0.0.1:8004 VW_SSO_SUBJECT_URL=http://127.0.0.1:8084 \
    VW_RSA_KEY="${work}/subject/rsa_key.pem" VW_SERVICES_CA="${work}/ca.pem" VW_SERVICES_HOST=127.0.0.1:2503 \
    vendor/bin/phpunit --testsuite Differential "$@" || status=$?
if [[ "${status}" != 0 ]]; then
    for log in "${work}"/*.log; do
        echo "--- ${log}"
        tail -30 "${log}"
    done
fi
exit "${status}"
