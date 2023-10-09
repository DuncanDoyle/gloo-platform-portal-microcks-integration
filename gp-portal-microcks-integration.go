package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"strconv"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"

	microcksClient "github.com/JulienBreux/microcks-client-go"
	log "github.com/sirupsen/logrus"
)

const GP_PORTAL_SERVER_ENDPOINT_VARNAME = "GP_PORTAL_SERVER_ENDPOINT"
const MICROCKS_API_SERVER_ENDPOINT_VARNAME = "MICROCKS_API_SERVER_ENDPOINT"
const MICROCKS_TOKEN_ENDPOINT_VARNAME = "MICROCKS_TOKEN_ENDPOINT"
const MICROCKS_CLIENT_ID_VARNAME = "MICROCKS_CLIENT_ID"
const MICROCKS_CLIENT_SECRET_VARNAME = "MICROCKS_CLIENT_SECRET"
const LOG_LEVEL_VARNAME = "LOG_LEVEL"
const SKIP_TLS_VERIFY_VARNAME = "SKIP_TLS_VERIFY"

var gpPortalServerEndpoint string
var microcksApiServerEndpoint string
var microcksTokenEndpoint string
var microcksClientId string
var microcksClientSecret string
var logLevel string
var skipTlsVerify bool

type apiProduct struct {
	ApiProductDisplayName string       `json:"apiProductDisplayName"`
	ApiProductId          string       `json:"apiProductId"`
	ApiVersions           []apiVersion `json:"apiVersions"`
}

// Attach String() function to apiProduct type.
func (a apiProduct) String() string {
	return fmt.Sprintf("ApiProductDisplayName: %s, ApiProductId: %s, nr of ApiVersions: %d", a.ApiProductDisplayName, a.ApiProductId, len(a.ApiVersions))
}

type apiVersion struct {
	ApiId               string                 `json:"apiId"`
	ApiVersion          string                 `json:"apiVersion"`
	Contact             string                 `json:"contact"`
	CustomMetadata      map[string]string      `json:"customMetadata"`
	Description         string                 `json:"description"`
	License             string                 `json:"license"`
	Lifecycle           string                 `json:"lifecycle"`
	OpenapiSpec         map[string]interface{} `json:"openapiSpec"`
	OpenapiSpecFetchErr string                 `json:"openapiSpecFetchErr"`
	TermsOfService      string                 `json:"termsOfService"`
	Title               string                 `json:"title"`
	UsagePlans          []string               `json:"usagePlans"`
}

func (a apiVersion) String() string {
	return fmt.Sprintf("ApiId: %s, ApiVersion: %s", a.ApiId, a.ApiVersion)
}

func main() {
	log.Info("Syncing PortalServer APIs with Microcks.")
	parseConfig()

	//Fetch the API Products
	apiProducts := fetchApisFromPortalServer()

	var oasSchema map[string]interface{}

	//Register all API Versions with Microcks
	for i, apiProduct := range apiProducts {
		log.Debug("Index: '" + strconv.Itoa(i) + "', apiProduct: " + apiProduct.String())
		apiVersions := apiProduct.ApiVersions
		for _, apiVersion := range apiVersions {
			log.Debug("ApiVersion: " + apiVersion.String())
			oasSchema = apiVersion.OpenapiSpec
			registerOpenApiSpecification(apiProduct.ApiProductId, apiVersion.ApiVersion, oasSchema)
		}
	}
}

func parseConfig() {
	log.Info("Parsing configuration")

	logLevel, err := log.ParseLevel(os.Getenv(LOG_LEVEL_VARNAME))
	if err != nil {
		logLevel = log.InfoLevel
	}
	log.Info("Setting logLevel to: " + logLevel.String())
	log.SetLevel(logLevel)

	gpPortalServerEndpoint = os.Getenv(GP_PORTAL_SERVER_ENDPOINT_VARNAME)
	microcksApiServerEndpoint = os.Getenv(MICROCKS_API_SERVER_ENDPOINT_VARNAME)
	microcksTokenEndpoint = os.Getenv(MICROCKS_TOKEN_ENDPOINT_VARNAME)
	microcksClientId = os.Getenv(MICROCKS_CLIENT_ID_VARNAME)
	microcksClientSecret = os.Getenv(MICROCKS_CLIENT_SECRET_VARNAME)
	//Set string value to temp variable. Will parse to bool later inn this function.
	skipTlsVerifyValue := os.Getenv(SKIP_TLS_VERIFY_VARNAME)

	if gpPortalServerEndpoint == "" {
		log.Fatal("Gloo Platform PortalServer endpoint has not been configured.")
		os.Exit(1)
	}
	if microcksApiServerEndpoint == "" {
		log.Fatal("Microcks API Server endpoint has not been configured.")
		os.Exit(1)
	}
	if microcksTokenEndpoint == "" {
		log.Fatal("Microcks Token endpoint has not been configured.")
		os.Exit(1)
	}
	if microcksClientId == "" {
		log.Fatal("Microcks client-id has not been configured.")
		os.Exit(1)
	}

	if microcksClientSecret == "" {
		log.Fatal("Microcks client-secret has not been configured.")
		os.Exit(1)
	}

	if skipTlsVerifyValue != "" {
		skipTlsVerify, err = strconv.ParseBool(skipTlsVerifyValue)
		if err != nil {
			log.Fatal("SKIP_TLS_VERIFY configuration expects a boolean value. Found: " + skipTlsVerifyValue)
		}
	} else {
		//Probably not necessary, as "false" is default.
		skipTlsVerify = false
	}

	log.Info("Initialized with the following values:" +
		"\n- PortalServer Endpoint: " + gpPortalServerEndpoint +
		"\n- Microcks API Server Endpoint: " + microcksApiServerEndpoint +
		"\n- Microcks Token Endpoint: " + microcksTokenEndpoint)
}

/**
 * Fetches the APIs with their OpenAPI Specification from the PortalServer.
 *
 * TODO: Add support for OAuth access-token based authentication.
 */
func fetchApisFromPortalServer() []apiProduct {
	getApisUrl := gpPortalServerEndpoint + "/apis?includeSchema=true"

	resp, getErr := http.Get(getApisUrl)
	if getErr != nil {
		log.Fatal(getErr)
	}

	//Read the body.
	getApiResponseBody, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		log.Fatal(readErr)
	}
	log.Debug(string(getApiResponseBody))

	var apiProducts []apiProduct
	jsonErr := json.Unmarshal(getApiResponseBody, &apiProducts)
	if jsonErr != nil {
		log.Fatal(jsonErr)
	}

	log.Debug("Fetched " + strconv.Itoa(len(apiProducts)) + " API Products.")
	return apiProducts
}

/**
 * Registers the given OpenAPI Specification definition with Microcks.
 */
func registerOpenApiSpecification(apiProductName string, apiProductVersion string, oasSchema map[string]interface{}) error {
	ctx := context.Background()

	log.Info("Registering OpenAPI Specification in Microcks for apiProduct version: " + apiProductName + "-" + apiProductVersion)

	b := new(bytes.Buffer)
	json.NewEncoder(b).Encode(oasSchema)

	// Create a multipart request body, reading the file.
	uploadArtifactRequestBody := &bytes.Buffer{}
	writer := multipart.NewWriter(uploadArtifactRequestBody)
	part, err := writer.CreateFormFile("file", "catstronauts-1.0.json")
	if err != nil {
		log.Fatal(err)
	}
	_, err = io.Copy(part, b)
	if err != nil {
		panic(err.Error())
	}

	// Add the mainArtifact flag to request.
	_ = writer.WriteField("mainArtifact", strconv.FormatBool(true))

	err = writer.Close()
	if err != nil {
		log.Fatal(err)
	}

	//Use the Microcks client to upload artifacts
	//Seems like this client was generated with https://github.com/deepmap/oapi-codegen

	var client *microcksClient.ClientWithResponses

	if skipTlsVerify {
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		sslcli := &http.Client{Transport: tr}
		ctx = context.WithValue(ctx, oauth2.HTTPClient, sslcli)

		skipTlsHtppClientOption := microcksClient.WithHTTPClient(sslcli)
		client, err = microcksClient.NewClientWithResponses(microcksApiServerEndpoint, skipTlsHtppClientOption)
	} else {
		client, err = microcksClient.NewClientWithResponses(microcksApiServerEndpoint)
	}

	if err != nil {
		log.Fatal(err)
	}

	//TODO: Do something more smart with the AccessToken, as we're fetching a new on every single call.
	//		It would be better if we fetch it, cache it, and refetch it when it's almost expired.
	oauthToken := fetchOAuthAccessToken(microcksTokenEndpoint, microcksClientId, microcksClientSecret)

	//Use a callback function to set the HTTP Request header.
	authHeaderRequestEditor := func(ctx context.Context, req *http.Request) error {
		req.Header.Add("Authorization", "Bearer: "+oauthToken.AccessToken)
		return nil
	}

	//Create an object and get the pointer (see https://www.quora.com/Whats-the-difference-between-and-new-on-Golang for explanation of pointers and dereferencing of vars)
	puaParams := new(microcksClient.UploadArtifactParams)
	puaParams.MainArtifact = true

	//Upload the artifacts.
	uploadResponse, err := client.UploadArtifactWithBody(ctx, puaParams, writer.FormDataContentType(), uploadArtifactRequestBody, authHeaderRequestEditor)
	if err != nil {
		log.Fatal(err)
	}
	if uploadResponse != nil {
		log.Debug("Upload response status: " + strconv.Itoa(uploadResponse.StatusCode))
		if uploadResponse.StatusCode != 201 {
			log.Error("Error uploading OpenAPI Specification for api: " + apiProductName + "-" + apiProductVersion)
		}
	}
	return nil
}

func fetchMicrocksKeycloakConfiguration() {
	//Use the Microcks client to upload artifacts
	//Seems like this client was generated with https://github.com/deepmap/oapi-codegen
	client, err := microcksClient.NewClientWithResponses(microcksApiServerEndpoint)
	if err != nil {
		log.Fatal(err)
	}

	//TODO: Do something more smart with the AccessToken, as we're fetching a new on every single call.
	//		It would be better if we fetch it, cache it, and refetch it when it's almost expired.
	oauthToken := fetchOAuthAccessToken(microcksTokenEndpoint, microcksClientId, microcksClientSecret)

	ctx := context.Background()

	//Use a callback function to set the HTTP Request header.
	authHeaderRequestEditor := func(ctx context.Context, req *http.Request) error {
		req.Header.Add("Authorization", "Bearer: "+oauthToken.AccessToken)
		return nil
	}
	mcKeycloakConfigResponse, err := client.GetKeycloakConfigWithResponse(ctx, authHeaderRequestEditor)
	if err != nil {
		log.Fatal(err)
	}
	// Print the response
	log.Debug("\nKeycloak Config Response:")
	log.Debug(mcKeycloakConfigResponse.JSON200)
}

/**
 * Fetches the OAuth access-token from the given `tokenEndpoint` using the `clientId` and `clientSecret`.
 */
func fetchOAuthAccessToken(tokenEndpoint string, clientId string, clientSecret string) *oauth2.Token {

	ctx := context.Background()

	log.Debug("Fetching OAuth2 AccessToken.")
	clientCredentialsConfig := clientcredentials.Config{
		ClientID:     microcksClientId,
		ClientSecret: microcksClientSecret,
		TokenURL:     microcksTokenEndpoint,
	}
	if skipTlsVerify {
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		sslcli := &http.Client{Transport: tr}
		ctx = context.WithValue(ctx, oauth2.HTTPClient, sslcli)
	}

	token, oauthErr := clientCredentialsConfig.Token(ctx)
	if oauthErr != nil {
		log.Fatal(oauthErr)
	}
	return token
}
