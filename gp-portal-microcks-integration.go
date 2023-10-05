package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"mime/multipart"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"

	microcksClient "github.com/JulienBreux/microcks-client-go"
	log "github.com/sirupsen/logrus"
)

const gpPortalServerEndpoint = "http://developer.example.com/v1"
const microcksApiServerEndpoint = "http://localhost:8080/api"
const microcksTokenEndpoint = "http://localhost:18080/realms/microcks/protocol/openid-connect/token"
const microcksClientId = "microcks-serviceaccount"
const microcksClientSecret = "ab54d329-e435-41ae-a900-ec6b3fe15c54"

type apiProduct struct {
	ApiProductDisplayName string                   `json:"apiProductDisplayName"`
	ApiProductId          string                   `json:"apiProductId"`
	ApiVersions           []apiVersion				`json:"apiVersions"`
}

// Attach String() function to apiProduct type.
func (a apiProduct) String() string {
	return fmt.Sprintf("ApiProductDisplayName: %s, ApiProductId: %s, nr of ApiVersions: %d", a.ApiProductDisplayName, a.ApiProductId, len(a.ApiVersions))
}

type apiVersion struct {
	ApiId				string						`json:"apiId"`
	ApiVersion			string						`json:"apiVersion"`
	Contact				string						`json:"contact"`
	CustomMetadata		map[string]string			`json:"customMetadata"`
	Description			string						`json:"description"`
	License				string 						`json:"license"`
	Lifecycle			string						`json:"lifecycle"`
	OpenapiSpec			map[string]interface{}		`json:"openapiSpec"`
	OpenapiSpecFetchErr	string 						`json:"openapiSpecFetchErr"`
	TermsOfService		string						`json:"termsOfService"`
	Title				string  					`json:"title"`
	UsagePlans			[]string					`json:"usagePlans"`
}

func (a apiVersion) String() string {
	return fmt.Sprintf("ApiId: %s, ApiVersion: %s", a.ApiId, a.ApiVersion)
}

func main() {
	log.Info("Syncing PortalServer APIs with Microcks.")

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
	log.Info("Registering OpenAPI Specification for apiProduct version: " + apiProductName + "-" + apiProductVersion);

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
		req.Header.Add("Authorization", "Bearer: " + oauthToken.AccessToken)
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
			log.Error("Error uploading OpenAPI Specification for api: " + apiProductName + "-" + apiProductVersion);
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
		req.Header.Add("Authorization", "Bearer: " + oauthToken.AccessToken)
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
	log.Debug("Fetching OAuth2 AccessToken.")
	clientCredentialsConfig := clientcredentials.Config {
		ClientID: microcksClientId,
		ClientSecret: microcksClientSecret,
		TokenURL: microcksTokenEndpoint,
	}
	
	token, oauthErr := clientCredentialsConfig.Token(context.Background())
	if oauthErr != nil {
		log.Fatal(oauthErr)
	}
	return token
}
