package middleware

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"GoAuth/models"
	"GoAuth/services"

	"github.com/MintzyG/GoResponse/response"
	"github.com/golang-jwt/jwt/v5"
	"github.com/spf13/viper"
	"github.com/ua-parser/uap-go/uaparser"
)

var uaParser = uaparser.NewFromSaved()

func AuthMiddleware(authService *services.AuthService) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			publicKeyPEM := []byte(viper.GetString("JWT_PUBLIC_KEY"))
			publicKey, err := jwt.ParseRSAPublicKeyFromPEM(publicKeyPEM)
			if err != nil {
				response.InternalServerError("failed to parse public key").
					AddTrace(err).WithModule("auth").Send(w)
				return
			}

			accessHeader := r.Header.Get("Authorization")
			if accessHeader == "" {
				response.Unauthorized("authorization header required").WithModule("auth").Send(w)
				return
			}
			if !strings.HasPrefix(accessHeader, "Bearer ") {
				response.Unauthorized("authorization header format must be Bearer {token}").WithModule("auth").Send(w)
				return
			}
			accessTokenString := strings.TrimPrefix(accessHeader, "Bearer ")

			refreshHeader := r.Header.Get("Refresh")
			if refreshHeader == "" {
				response.Unauthorized("refresh token required").WithModule("auth").Send(w)
				return
			}
			if !strings.HasPrefix(refreshHeader, "Bearer ") {
				response.Unauthorized("refresh header format must be Bearer {token}").WithModule("auth").Send(w)
				return
			}
			refreshTokenString := strings.TrimPrefix(refreshHeader, "Bearer ")

			accessToken, accessErr := jwt.ParseWithClaims(accessTokenString, &models.UserClaims{}, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
					return nil, errors.New("unexpected signing method for access token")
				}
				return publicKey, nil
			})

			refreshToken, refreshErr := jwt.ParseWithClaims(refreshTokenString, &jwt.MapClaims{}, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
					return nil, errors.New("unexpected signing method for refresh token")
				}
				return publicKey, nil
			})

			if accessErr != nil && !strings.Contains(accessErr.Error(), "token is expired") {
				response.Unauthorized("invalid access token: " + accessErr.Error()).WithModule("auth").Send(w)
				return
			}
			if refreshErr != nil {
				response.Unauthorized("invalid refresh token: " + refreshErr.Error()).WithModule("auth").Send(w)
				return
			}
			if !refreshToken.Valid {
				response.Unauthorized("refresh token expired or invalid").WithModule("auth").Send(w)
				return
			}

			refreshClaims, ok := refreshToken.Claims.(*jwt.MapClaims)
			if !ok {
				response.Unauthorized("invalid refresh token claims").WithModule("auth").Send(w)
				return
			}

			userID, ok := (*refreshClaims)["id"].(string)
			if !ok {
				response.Unauthorized("missing user_id in refresh token").WithModule("auth").Send(w)
				return
			}

			tokenUA, _ := (*refreshClaims)["user_agent"].(string)
			currentUA := r.UserAgent()

			tokenClient := uaParser.Parse(tokenUA)
			currentClient := uaParser.Parse(currentUA)

			// Compare device family and browser family
			if tokenClient.UserAgent.Family != "" && currentClient.UserAgent.Family != "" &&
				tokenClient.UserAgent.Family != currentClient.UserAgent.Family ||
				tokenClient.Device.Family != "" && currentClient.Device.Family != "" &&
					tokenClient.Device.Family != currentClient.Device.Family {
				response.Unauthorized("refresh token used from another device or browser").WithModule("auth").Send(w)
				return
			}

			storedToken, err := authService.FindRefreshToken(userID, refreshTokenString)
			if err != nil || storedToken == nil {
				response.Unauthorized("refresh token not found or revoked").WithModule("auth").Send(w)
				return
			}

			if accessToken != nil && accessToken.Valid {
				accessClaims, _ := accessToken.Claims.(*models.UserClaims)
				ctx := context.WithValue(r.Context(), models.UserContextValue, accessClaims)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			response.Unauthorized("user has invalid tokens").WithModule("auth").Send(w)
		})
	}
}
