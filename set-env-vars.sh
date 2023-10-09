#!/bin/sh

export GP_PORTAL_SERVER_ENDPOINT="http://developer.example.com/v1"
#export MICROCKS_API_SERVER_ENDPOINT="http://localhost:8080/api"
export MICROCKS_API_SERVER_ENDPOINT="https://microcks.example.com/api"
#export MICROCKS_TOKEN_ENDPOINT="http://localhost:18080/realms/microcks/protocol/openid-connect/token"
export MICROCKS_TOKEN_ENDPOINT="https://mc-keycloak.example.com/realms/microcks/protocol/openid-connect/token"
export MICROCKS_CLIENT_ID="microcks-serviceaccount"
export MICROCKS_CLIENT_SECRET="ab54d329-e435-41ae-a900-ec6b3fe15c54"
export LOG_LEVEL=DEBUG
export SKIP_TLS_VERIFY=true