#!/bin/sh

# require docker & jq

script_dir=$(cd "${0%/*}"; pwd)

KC_CONTAINER_NAME="keycloak_dev"
KC_DOCKER_IMAGE="jboss/keycloak"
KC_ADMIN="admin"
KC_PWD="admin"

KC_URL="http://localhost:8080/auth"
KC_USERS="user1 user2 admin1 superadmin1"

# ensure local keycloak is running
if [ ! "$(docker ps -q -f name=${KC_CONTAINER_NAME})" ]; then
    if [ "$(docker ps -aq -f status=exited -f name=${KC_CONTAINER_NAME})" ]; then
        echo -n "${KC_CONTAINER_NAME} already exist. (rm & recreate) or start ? (start | rm): "
        read resp
        if [ "${resp}" = "rm" ]
        then
          # cleanup
          docker rm "${KC_CONTAINER_NAME}"
        elif [ "${resp}" = "start" ]
        then
          docker start "${KC_CONTAINER_NAME}"
          echo "Enjoy!"
          exit 0
        else
          echo "You must choose between 'start' or 'rm'."
          echo "Bye."
          exit 1
        fi
    fi
    # run your container
    docker run -d --name "${KC_CONTAINER_NAME}" \
    -e KEYCLOAK_USER="${KC_ADMIN}" -e KEYCLOAK_PASSWORD="${KC_PWD}" \
    -p8080:8080 \
    "${KC_DOCKER_IMAGE}"
else
    echo "Container ${KC_CONTAINER_NAME} alreay running."
    echo "Bye..."
    exit 0
fi

echo "Wating for Keycloak docker..."

for i in `seq 1 12`;
do
  sleep 5
  echo -n "."
done
echo " Keycloak should run..."
echo "Wait for dev realm import..."

# get KC admin token
TKN=`curl -s -X POST \
  ${KC_URL}/realms/master/protocol/openid-connect/token \
  -H 'Accept: application/json' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -H 'cache-control: no-cache' \
  -d "grant_type=password&username=${KC_ADMIN}&password=${KC_PWD}&client_id=admin-cli" \
  | jq -r '.access_token'`

# import dev realm
curl -s -X POST \
  "${KC_URL}/admin/realms/" \
  --header "Authorization: Bearer ${TKN}" \
  --header 'Content-Type: application/json' \
  --data-raw "$(cat ${script_dir}/dev-realm.json)"

echo "Dev realm imported."

# create users with passwords
for user in $(echo ${KC_USERS})
do
echo "==="
  echo "Create ${user} with password ${user}"
  # new user
  curl -s -X POST \
    "${KC_URL}/admin/realms/dev/users" \
    --header "Authorization: Bearer ${TKN}" \
    --header 'Content-Type: application/json' \
    --data-raw "{\"username\": \"${user}\", \"enabled\": \"True\"}"
  echo -n "."

  # get user id
  user_id=$(curl -s -X GET "${KC_URL}/admin/realms/dev/users/?username=${user}" \
    -H "Accept: application/json" \
    -H "Authorization: Bearer $TKN" | jq --raw-output '.[0]["id"]')
  echo -n "."

  # set user password
  curl -s -X PUT \
    "${KC_URL}/admin/realms/dev/users/${user_id}/reset-password" \
    --header "Authorization: Bearer ${TKN}" \
    --header 'Content-Type: application/json' \
    --data-raw "{\"type\": \"password\", \"value\": \"${user}\"}"
    echo -n "."
    echo "Done"
done

echo "All users are created."

echo "Get client secret..."

# Get client secret
client_id=$(curl -s -X GET "${KC_URL}/admin/realms/dev/clients?clientId=dev-api" \
  -H "Accept: application/json" \
  -H "Authorization: Bearer $TKN" | jq --raw-output '.[0]["id"]')

client_secret=$(curl -s -X POST "${KC_URL}/admin/realms/dev/clients/${client_id}/client-secret" \
    -H "Accept: application/json" \
    -H "Authorization: Bearer $TKN" | jq --raw-output '.["value"]')

echo "Put this in your 'client_secrets.json' to work with local keycloak:"
echo "
{
    \"web\": {
        \"issuer\": \"${KC_URL}/realms/dev\",
        \"auth_uri\": \"${KC_URL}/realms/dev/protocol/openid-connect/auth\",
        \"client_id\": \"dev-api\",
        \"client_secret\": \"${client_secret}\",
        \"redirect_uris\": [
            \"http://localhost:5000/*\"
        ],
        \"userinfo_uri\": \"${KC_URL}/realms/dev/protocol/openid-connect/userinfo\",
        \"token_uri\": \"${KC_URL}/realms/dev/protocol/openid-connect/token\",
        \"token_introspection_uri\": \"${KC_URL}/realms/dev/protocol/openid-connect/token/introspect\",
        \"admin_uri\": \"${KC_URL}/admin/realms/dev\"
    }
}"

echo "Local Keycloak is available at ${KC_URL}."
echo "Login = ${KC_ADMIN} / Password = ${KC_PWD}"
echo "Enjoy !"
