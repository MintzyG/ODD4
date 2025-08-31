package middleware

import (
	"context"
	"net/http"
	"strings"

	"GoAuth/models"
	"GoAuth/services"
	u "GoAuth/utilities"

	"github.com/golang-jwt/jwt/v5"
	"github.com/spf13/viper"
)

func AuthMiddleware(authService *services.AuthService) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			secretKey := viper.GetString("JWT_SECRET")

			accessHeader := r.Header.Get("Authorization")
			if accessHeader == "" {
				u.SendError(w, []string{"authorization header is required"}, "auth-middleware", http.StatusUnauthorized)
				return
			}

			if !strings.HasPrefix(accessHeader, "Bearer ") {
				u.SendError(w, []string{"authorization header format must be Bearer {token}"}, "auth-middleware", http.StatusUnauthorized)
				return
			}
			accessTokenString := strings.TrimPrefix(accessHeader, "Bearer ")

			refreshHeader := r.Header.Get("Refresh")
			if refreshHeader == "" {
				u.SendError(w, []string{"refresh token required for access"}, "auth-middleware", http.StatusUnauthorized)
				return
			}

			if !strings.HasPrefix(refreshHeader, "Bearer ") {
				u.SendError(w, []string{"refresh header format must be \"Bearer {token}\""}, "auth-middleware", http.StatusUnauthorized)
				return
			}
			refreshTokenString := strings.TrimPrefix(refreshHeader, "Bearer ")

			accessToken, accessTokenErr := jwt.ParseWithClaims(accessTokenString, &models.UserClaims{}, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, jwt.ErrSignatureInvalid
				}
				return []byte(secretKey), nil
			})

			refreshToken, refreshErr := jwt.ParseWithClaims(refreshTokenString, &jwt.MapClaims{}, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, jwt.ErrSignatureInvalid
				}
				return []byte(secretKey), nil
			})

			if accessTokenErr != nil && !strings.Contains(accessTokenErr.Error(), "token is expired") {
				u.SendError(w, []string{"invalid access token: " + accessTokenErr.Error()}, "auth-middleware", http.StatusUnauthorized)
				return
			}

			var accessClaims *models.UserClaims
			var ok bool

			if accessToken != nil {
				accessClaims, ok = accessToken.Claims.(*models.UserClaims)
				if !ok {
					u.SendError(w, []string{"invalid access token claims"}, "auth-middleware", http.StatusUnauthorized)
					return
				}
			}

			if refreshErr != nil {
				u.SendError(w, []string{"invalid refresh token: " + refreshErr.Error()}, "auth-middleware", http.StatusUnauthorized)
				return
			}

			if !refreshToken.Valid {
				u.SendError(w, []string{"refresh token is expired or invalid"}, "auth-middleware", http.StatusUnauthorized)
				return
			}

			refreshClaims, ok := refreshToken.Claims.(*jwt.MapClaims)
			if !ok {
				u.SendError(w, []string{"invalid refresh token claims"}, "auth-middleware", http.StatusUnauthorized)
				return
			}

			userID, ok := (*refreshClaims)["id"].(string)
			if !ok {
				u.SendError(w, []string{"invalid user_id in refresh token"}, "auth-middleware", http.StatusUnauthorized)
				return
			}

			storedToken, err := authService.FindRefreshToken(userID, refreshTokenString)
			if err != nil || storedToken == nil {
				u.SendError(w, []string{"refresh token not found or revoked"}, "auth-middleware", http.StatusUnauthorized)
				return
			}

			if accessToken != nil && accessToken.Valid {
				ctx := context.WithValue(r.Context(), models.UserContextValue, accessClaims)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			user, err := authService.AuthRepo.FindUserByID(userID)
			if err != nil {
				u.SendError(w, []string{"request user not found"}, "auth-middleware", http.StatusUnauthorized)
				return
			}

			newAccessToken, err := authService.GenerateAcessToken(user)
			if err != nil {
				u.SendError(w, []string{"failed to generate new access token"}, "auth-middleware", http.StatusInternalServerError)
				return
			}

			newRefreshToken, err := authService.GenerateRefreshToken(user.ID, r)
			if err != nil {
				u.SendError(w, []string{"failed to generate new refresh token"}, "auth-middleware", http.StatusInternalServerError)
				return
			}

			if err := authService.AuthRepo.UpdateRefreshToken(user.ID, refreshTokenString, newRefreshToken); err != nil {
				u.SendError(w, []string{"failed to update refresh token"}, "auth-middleware", http.StatusInternalServerError)
				return
			}

			newAccessJWT, _ := jwt.ParseWithClaims(newAccessToken, &models.UserClaims{}, func(token *jwt.Token) (interface{}, error) {
				return []byte(secretKey), nil
			})

			newAccessClaims, _ := newAccessJWT.Claims.(*models.UserClaims)

			w.Header().Set("X-New-Access-Token", newAccessToken)
			w.Header().Set("X-New-Refresh-Token", newRefreshToken)

			ctx := context.WithValue(r.Context(), models.UserContextValue, newAccessClaims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
