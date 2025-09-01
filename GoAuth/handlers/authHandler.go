package handlers

import (
	ae "GoAuth/erorrs"
	"GoAuth/models"
	"GoAuth/services"
	"GoAuth/validation"
	"net/http"
	"strconv"
	"strings"

	"github.com/MintzyG/GoResponse/response"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jinzhu/copier"
	"github.com/spf13/viper"
)

type AuthHandler struct {
	AuthService *services.AuthService
}

func NewAuthHandler(service *services.AuthService) *AuthHandler {
	return &AuthHandler{AuthService: service}
}

// TODO: ADD ERROR STATE IF MISSING SEND
// Register godoc
// @Summary      Register new user and send a verification email
// @Description  Register a new user in the system, generates a verification code that is stored
// @Description  in the database for 24 hours and sent in a verification email to the user
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        request body UserRegisterRequest true "User registration info"
// @Success      201  {object}  NoMessageSuccessResponse{data=AuthTokensResponse}
// @Failure      400  {object}  AuthStandardErrorResponse
// @Failure      401  {object}  AuthStandardErrorResponse
// @Router       /register [post]
func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var user models.UserRegisterRequest
	resp := validation.ValidateWith(r, &user)
	if resp != nil {
		resp.SendWithContext(r.Context(), w)
		return
	}

	var err error
	if err = h.AuthService.Register(user); err != nil {
		response.BadRequest("error registering user").AddTrace(err).WithModule("auth").Send(w)
		return
	}

	var login models.UserLoginRequest
	copier.Copy(&login, &user)

	var data models.AuthTokensResponse
	if data.AccessToken, data.RefreshToken, err = h.AuthService.Login(login, r); err != nil {
		response.BadRequest("error trying to login").AddTrace(err).WithModule("auth").Send(w)
		return
	}

	response.Created().WithModule("auth").WithData(data).Send(w)
}

// Login godoc
// @Summary      Logs in the user
// @Description  Logging successfully creates a refresh token in the database so the user can
// @Description  invalidate specific session from any other session\n
// @Description  Returns both an Access Token of 5 minutes duration and a Refresh Token of 2 days duration
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        request body models.UserLoginRequest true "User login info"
// @Success      200  {object}  NoMessageSuccessResponse{data=AuthTokensResponse}
// @Failure      400  {object}  AuthStandardErrorResponse
// @Failure      401  {object}  AuthStandardErrorResponse
// @Router       /login [post]
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var user models.UserLoginRequest
	resp := validation.ValidateWith(r, &user)
	if resp != nil {
		resp.SendWithContext(r.Context(), w)
		return
	}

	var data models.AuthTokensResponse
	var err error
	if data.AccessToken, data.RefreshToken, err = h.AuthService.Login(user, r); err != nil {
		response.Unauthorized("error trying to login").AddTrace(err).WithModule("auth").Send(w)
		return
	}

	response.OK("logged in successfully").WithModule("auth").WithData(data).Send(w)
}

// Logout godoc
// @Summary      Logs out the user
// @Description  Invalidates the refresh token used in the request in the database, effectively logging out the user from the current session
// @Tags         auth
// @Accept       json
// @Produce      json
// @Security     Bearer
// @Param        Authorization header string true "Bearer {access_token}"
// @Param        Refresh header string true "Bearer {refresh_token}"
// @Success      200  {object}  NoDataSuccessResponse
// @Failure      401  {object}  AuthStandardErrorResponse
// @Router       /logout [post]
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	user, err := getUserFromContext(h.AuthService.AuthRepo.FindUserByID, r)
	if err != nil {
		response.BadRequest().AddTrace(ae.ErrContext, err).WithModule("auth").Send(w)
		return
	}

	refreshHeader := r.Header.Get("Refresh")
	refreshTokenString := strings.TrimPrefix(refreshHeader, "Bearer ")

	err = h.AuthService.Logout(user.ID, refreshTokenString)
	if err != nil {
		response.BadRequest("error trying to logout").AddTrace(err).WithModule("auth").Send(w)
		return
	}

	response.OK("logged out successfully").WithModule("auth").Send(w)
}

// RevokeRefreshToken godoc
// @Summary      Revoke a refresh token
// @Description  Invalidates a specific refresh token for the authenticated user
// @Description  Can't be passed the same refresh token the user is using to access the route
// @Tags         auth
// @Accept       json
// @Produce      json
// @Security     Bearer
// @Param        Authorization header string true "Bearer {access_token}"
// @Param        Refresh header string true "Bearer {refresh_token}"
// @Param        request body models.RevokeTokenRequest true "Refresh token to revoke"
// @Success      200  {object}  NoDataSuccessResponse
// @Failure      400  {object}  AuthStandardErrorResponse
// @Failure      401  {object}  AuthStandardErrorResponse
// @Router       /revoke-refresh-token [post]
func (h *AuthHandler) RevokeRefreshToken(w http.ResponseWriter, r *http.Request) {
	user, err := getUserFromContext(h.AuthService.AuthRepo.FindUserByID, r)
	if err != nil {
		response.BadRequest().AddTrace(ae.ErrContext, err).WithModule("auth").Send(w)
		return
	}

	var req models.RevokeTokenRequest
	if resp := validation.ValidateWith(r, &req); resp != nil {
		resp.SendWithContext(r.Context(), w)
		return
	}

	if err := h.AuthService.RevokeRefreshToken(user.ID, req.Token); err != nil {
		response.BadRequest("error revoking token").AddTrace(err).WithModule("auth").Send(w)
		return
	}

	response.OK("refresh token revoked successfully").WithModule("auth").Send(w)
}

// VerifyAccount godoc
// @Summary      Verify user account with token
// @Description  Validates the verification token sent to user's email and marks the account as verified
// @Tags         auth
// @Accept       json
// @Produce      json
// @Security     Bearer
// @Param        Authorization header string true "Bearer {access_token}"
// @Param        Refresh header string true "Bearer {refresh_token}"
// @Param        request body VerifyAccountRequest true "Verification token from email"
// @Success      200  {object}  NoDataSuccessResponse
// @Failure      400  {object}  AuthStandardErrorResponse
// @Failure      401  {object}  AuthStandardErrorResponse
// @Router       /verify-account [post]
func (h *AuthHandler) VerifyAccount(w http.ResponseWriter, r *http.Request) {
	user, err := getUserFromContext(h.AuthService.AuthRepo.FindUserByID, r)
	if err != nil {
		response.BadRequest().AddTrace(ae.ErrContext, err).WithModule("auth").Send(w)
		return
	}

	var req models.VerifyAccountRequest
	if resp := validation.ValidateWith(r, &req); resp != nil {
		resp.SendWithContext(r.Context(), w)
		return
	}

	err = h.AuthService.VerifyUser(&user, req.Token)
	if err != nil {
		response.BadRequest("error verifying user").AddTrace(err).WithModule("auth").Send(w)
		return
	}

	refreshHeader := r.Header.Get("Refresh")
	refreshTokenString := strings.TrimPrefix(refreshHeader, "Bearer ")
	if err = h.AuthService.Logout(user.ID, refreshTokenString); err != nil {
		response.BadRequest("error logging out").AddTrace(err).WithModule("auth").Send(w)
		return
	}

	access_token, refresh_token, err := h.AuthService.GenerateTokenPair(user, r)
	if err != nil {
		response.BadRequest("error generating token pair").AddTrace(err).WithModule("auth").Send(w)
		return
	}

	w.Header().Set("X-New-Access-Token", access_token)
	w.Header().Set("X-New-Refresh-Token", refresh_token)

	response.OK("account verified").WithModule("auth").Send(w)
}

func (h *AuthHandler) ForgotPassword(w http.ResponseWriter, r *http.Request) {
	var req models.ForgotPasswordRequest
	if resp := validation.ValidateWith(r, &req); resp != nil {
		resp.SendWithContext(r.Context(), w)
		return
	}

	if err := h.AuthService.InitiatePasswordReset(req.Email); err != nil {
		response.BadRequest("error initiating password reset").AddTrace(err).WithModule("auth").Send(w)
		return
	}

	response.OK("password reset email sent").WithModule("auth").Send(w)
}

// ChangePassword godoc
// @Summary      Change user password
// @Description  Changes the user's password using a reset token
// @Tags         auth
// @Accept       json
// @Produce      json
// @Security     Bearer
// @Param        Authorization header string true "Bearer {access_token}"
// @Param        Refresh header string true "Bearer {refresh_token}"
// @Param        request body ChangePasswordRequest true "New password"
// @Success      200  {object}  NoDataSuccessResponse
// @Failure      400  {object}  AuthStandardErrorResponse
// @Failure      401  {object}  AuthStandardErrorResponse
// @Router       /change-password [post]
func (h *AuthHandler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	var secretKey string = viper.GetString("JWT_SECRET")
	resetToken := r.URL.Query().Get("token")
	if resetToken == "" {
		response.BadRequest("missing reset token").WithModule("auth").Send(w)
		return
	}

	var req models.ChangePasswordRequest
	if resp := validation.ValidateWith(r, &req); resp != nil {
		resp.SendWithContext(r.Context(), w)
		return
	}

	claims := &models.PasswordResetClaims{}
	token, err := jwt.ParseWithClaims(resetToken, claims, func(t *jwt.Token) (interface{}, error) {
		return []byte(secretKey), nil
	})

	if err != nil || !token.Valid || !claims.IsPasswordReset {
		response.BadRequest("invalid or expired reset token").WithModule("auth").Send(w)
		return
	}

	if err := h.AuthService.ChangePassword(claims.UserID, req.NewPassword); err != nil {
		response.BadRequest("error changing password").WithModule("auth").Send(w)
		return
	}

	response.OK("password changed succesfuly").WithModule("auth").Send(w)
}

// ResendVerificationCode godoc
// @Summary      Resend verification code
// @Description  Generates a new verification code and resends it to the authenticated user
// @Tags         auth
// @Accept       json
// @Produce      json
// @Security     Bearer
// @Param        Authorization header string true "Bearer {access_token}"
// @Param        Refresh header string true "Bearer {refresh_token}"
// @Success      200  {object}  NoDataSuccessResponse
// @Failure      400  {object}  AuthStandardErrorResponse
// @Failure      401  {object}  AuthStandardErrorResponse
// @Router       /resend-verification-code [post]
func (h *AuthHandler) ResendVerificationCode(w http.ResponseWriter, r *http.Request) {
	user, err := getUserFromContext(h.AuthService.AuthRepo.FindUserByID, r)
	if err != nil {
		response.BadRequest().AddTrace(ae.ErrContext, err).WithModule("auth").Send(w)
		return
	}

	if err := h.AuthService.ResendVerificationCode(&user); err != nil {
		response.BadRequest("error resending verification code").AddTrace(err).WithModule("auth").Send(w)
		return
	}

	response.OK("verification code sent").WithModule("auth").Send(w)
}

// SwitchEventCreatorStatus godoc
// @Summary      Toggle event creator status
// @Description  Switches a user's event creator status (enables/disables ability to create events). Only available to super users.
// @Tags         auth
// @Accept       json
// @Produce      json
// @Security     Bearer
// @Param        Authorization header string true "Bearer {access_token}"
// @Param        Refresh header string true "Bearer {refresh_token}"
// @Param        request body models.SwitchEventCreatorStatusRequest true "Target user email"
// @Success      200  {object}  NoDataSuccessResponse
// @Failure      400  {object}  AuthStandardErrorResponse
// @Failure      401  {object}  AuthStandardErrorResponse
// @Failure      403  {object}  AuthStandardErrorResponse
// @Router       /switch-event-creator-status [post]
func (h *AuthHandler) SwitchEventCreatorStatus(w http.ResponseWriter, r *http.Request) {
	user, err := getUserFromContext(h.AuthService.AuthRepo.FindUserByID, r)
	if err != nil {
		response.BadRequest().AddTrace(ae.ErrContext, err).WithModule("auth").Send(w)
		return
	}

	var req models.SwitchEventCreatorStatusRequest
	if resp := validation.ValidateWith(r, &req); resp != nil {
		resp.SendWithContext(r.Context(), w)
		return
	}

	if err := h.AuthService.SwitchEventCreatorStatus(user, req.Email); err != nil {
		if strings.Contains(err.Error(), "only superusers") {
			response.Forbidden("user lacks permission for this action").WithModule("auth").Send(w)
			return
		}
		response.BadGateway("error switching event creator status").AddTrace(err).WithModule("auth").Send(w)
		return
	}

	response.OK("event creator status switched successfully").WithModule("auth").Send(w)
}

// ChangeUserName godoc
// @Summary      Change user name
// @Description  Updates the authenticated user's first and last name
// @Tags         auth
// @Accept       json
// @Produce      json
// @Security     Bearer
// @Param        Authorization header string true "Bearer {access_token}"
// @Param        Refresh header string true "Bearer {refresh_token}"
// @Param        request body models.ChangeUserNameRequest true "New name information"
// @Success      200  {object}  NoDataSuccessResponse
// @Failure      400  {object}  AuthStandardErrorResponse
// @Failure      401  {object}  AuthStandardErrorResponse
// @Router       /change-name [post]
func (h *AuthHandler) ChangeUserName(w http.ResponseWriter, r *http.Request) {
	user, err := getUserFromContext(h.AuthService.AuthRepo.FindUserByID, r)
	if err != nil {
		response.BadRequest().AddTrace(ae.ErrContext, err).WithModule("auth").Send(w)
		return
	}

	var req models.ChangeUserNameRequest
	if resp := validation.ValidateWith(r, &req); resp != nil {
		resp.SendWithContext(r.Context(), w)
		return
	}

	if err := h.AuthService.ChangeUserName(user, req.Name, req.LastName); err != nil {
		response.BadRequest("error changing user name").AddTrace(err).WithModule("auth").Send(w)
		return
	}

	response.OK("user name changed successfully").WithModule("auth").Send(w)
}

// GetUsers godoc
// @Summary      Get users
// @Description  Get users with optional filters: ?id=123 for single user, ?page=1&limit=10 for pagination
// @Tags         auth
// @Accept       json
// @Produce      json
// @Security     Bearer
// @Param        Authorization header string true "Bearer {access_token}"
// @Param        Refresh header string true "Bearer {refresh_token}"
// @Param        id query string false "Get specific user by ID"
// @Param        page query int false "Page number (default: 1)"
// @Param        limit query int false "Items per page (default: 10)"
// @Success      200  {object}  NoMessageSuccessResponse{data=GetUsersResponse}
// @Failure      400  {object}  AuthStandardErrorResponse
// @Failure      401  {object}  AuthStandardErrorResponse
// @Failure      403  {object}  AuthStandardErrorResponse
// @Router       /users [get]
func (h *AuthHandler) GetUsers(w http.ResponseWriter, r *http.Request) {
	// Check if requesting specific user by ID
	if userID := r.URL.Query().Get("id"); userID != "" {
		targetUser, err := h.AuthService.GetUserByID(userID)
		if err != nil {
			response.NotFound("user not found").AddTrace(err).WithModule("auth").Send(w)
			return
		}

		var userDTO models.UserDTO
		copier.Copy(&userDTO, &targetUser)

		response.OK().WithModule("auth").WithData(userDTO).Send(w)
		return
	}

	// Parse pagination parameters
	page := 1
	limit := 10

	var pageStr string
	if pageStr = r.URL.Query().Get("page"); pageStr != "" {
		if p, err := strconv.Atoi(pageStr); err == nil && p > 0 {
			page = p
		}
	}

	var limitStr string
	if limitStr = r.URL.Query().Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 100 {
			limit = l
		}
	}

	if pageStr != "" || limitStr != "" {
		users, total, err := h.AuthService.GetUsers(page, limit)
		if err != nil {
			response.BadRequest("error retrieving users").AddTrace(err).WithModule("auth").Send(w)
			return
		}

		userResponses := make([]models.UserDTO, len(users))
		for i, u := range users {
			copier.Copy(&(userResponses[i]), &u)
		}

		totalPages := int((total + int64(limit) - 1) / int64(limit))
		response.OK().
			WithModule("auth").
			WithData(userResponses).
			WithPagination(response.PaginationParams{Page: page, Limit: limit}, int64(totalPages)).
			Send(w)
		return
	}

	users, err := h.AuthService.AuthRepo.GetAllUsers()
	if err != nil {
		response.InternalServerError("coudl'nt get all users").AddTrace(err).WithModule("auth").Send(w)
		return
	}

	var userDTO []models.UserDTO
	copier.Copy(&userDTO, &users)
	response.OK("retrieved all users").WithData(userDTO).WithModule("auth").Send(w)
}

func (h *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	refreshHeader := r.Header.Get("Refresh")
	if refreshHeader == "" || !strings.HasPrefix(refreshHeader, "Bearer ") {
		response.Unauthorized("refresh token required").WithModule("auth").Send(w)
		return
	}
	refreshToken := strings.TrimPrefix(refreshHeader, "Bearer ")

	var data models.AuthTokensResponse
	var err error
	data.AccessToken, data.RefreshToken, err = h.AuthService.RefreshTokens(refreshToken, r)
	if err != nil {
		response.Unauthorized().AddTrace(err).WithModule("auth").Send(w)
		return
	}

	response.OK().WithData(data).WithModule("auth").Send(w)
}
