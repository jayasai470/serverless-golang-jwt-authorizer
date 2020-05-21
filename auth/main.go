package main

import (
	"context"
	"errors"
	"log"
	"os"
	"strings"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/dgrijalva/jwt-go"
)

var auth = NewAuth(&Config{
	CognitoRegion:     os.Getenv("AWS_COGNITO_REGION"),
	CognitoUserPoolID: os.Getenv("AWS_COGNITO_USER_POOL_ID"),
})

// Strips 'Bearer ' prefix from bearer token string
func stripBearerPrefixFromTokenString(tok string) (string, error) {
	// Should be a bearer token
	if len(tok) > 6 && strings.ToUpper(tok[0:7]) == "BEARER " {
		return tok[7:], nil
	}
	return tok, nil
}

func extractToken(event events.APIGatewayProxyRequest) (string, error) {
	headers := event.Headers
	authTokenFromHeaders := headers["Authorization"]
	if authTokenFromHeaders != "" {
		return stripBearerPrefixFromTokenString(authTokenFromHeaders)
	}

	queryParams := event.QueryStringParameters
	authTokenFromQueryParams := queryParams["accessToken"]
	if authTokenFromQueryParams != "" {
		return authTokenFromQueryParams, nil
	}

	return "", errors.New("no token")
}

func buildProxyResponseForRestApi(jwtToken *jwt.Token, event events.APIGatewayProxyRequest) events.APIGatewayCustomAuthorizerResponse {
	claims := jwtToken.Claims.(jwt.MapClaims)
	awsAccountID := event.RequestContext.AccountID
	principalID := claims["username"].(string)
	resp := NewAuthorizerResponse(principalID, awsAccountID)
	resp.APIID = event.RequestContext.APIID
	resp.Stage = event.RequestContext.Stage
	resp.AllowAllMethods()
	resp.Context = map[string]interface{}{
		"email": claims["email"],
		"organization": claims["custom:organization"],
		"role": claims["custom:role"],
		"userId": claims["custom:userId"],
	}
	return resp.APIGatewayCustomAuthorizerResponse
}

func handleRequest(ctx context.Context, event events.APIGatewayProxyRequest) (events.APIGatewayCustomAuthorizerResponse, error) {
	accessToken, err := extractToken(event)
	if err != nil {
		return events.APIGatewayCustomAuthorizerResponse{}, errors.New("unauthorized")
	}

	jwtToken, err := auth.ParseJWT(accessToken)
	if err != nil {
		return events.APIGatewayCustomAuthorizerResponse{}, errors.New("unauthorized")
	}

	if !jwtToken.Valid {
		return events.APIGatewayCustomAuthorizerResponse{}, errors.New("unauthorized")
	}
	claims := jwtToken.Claims.(jwt.MapClaims)
	log.Println(claims)
	return buildProxyResponseForRestApi(jwtToken, event), nil
}

func init() {
	err := auth.CacheJWK()
	if err != nil {
		log.Fatalln("unable to start lambda")
	}
}

func main() {
	lambda.Start(handleRequest)
}