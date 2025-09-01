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

type AuthTokensResponse struct {
	AccessToken  string `json:"access_token" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."`
	RefreshToken string `json:"refresh_token" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."`
}

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
	if err = h.AuthService.Register(user.Email, user.Password, user.Name, user.LastName); err != nil {
		response.BadRequest("error registering user").AddTrace(err).WithModule("auth").Send(w)
		return
	}

	var data AuthTokensResponse
	if data.AccessToken, data.RefreshToken, err = h.AuthService.Login(user.Email, user.Password, r); err != nil {
		response.BadRequest("error trying to login").AddTrace(err).WithModule("auth").Send(w)
		return
	}

	// TODO: ADD ERROR STATE IF MISSING SEND
	response.Created().WithModule("auth").WithData(data).Send(w)
}

type UserLoginRequest struct {
	Email    string `json:"email" example:"user@example.com"`
	Password string `json:"password" example:"password123"`
}

// Login godoc
// @Summary      Logs in the user
// @Description  Logging successfully creates a refresh token in the database so the user can
// @Description  invalidate specific session from any other session\n
// @Description  Returns both an Access Token of 5 minutes duration and a Refresh Token of 2 days duration
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        request body UserLoginRequest true "User login info"
// @Success      200  {object}  NoMessageSuccessResponse{data=AuthTokensResponse}
// @Failure      400  {object}  AuthStandardErrorResponse
// @Failure      401  {object}  AuthStandardErrorResponse
// @Router       /login [post]
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var user models.UserLogin
	if err := decodeRequestBody(r, &user); err != nil {
		response.BadRequest().AddTrace(err).WithModule("auth").Send(w)
		return
	}

	acess_token, refresh, err := h.AuthService.Login(user.Email, user.Password, r)
	if err != nil {
		response.Unauthorized().WithMsg("error trying to login").AddTrace(err).WithModule("auth").Send(w)
		return
	}

	response.OK().WithModule("auth").WithData(map[string]string{"access_token": acess_token, "refresh_token": refresh}).Send(w)
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
		response.Unauthorized().WithMsg("error trying to logout").AddTrace(err).WithModule("auth").Send(w)
		return
	}

	response.OK().WithMsg("logged out successfully").WithModule("auth").Send(w)
}

type RevokeTokenRequest struct {
	Token string `json:"refresh_token" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."`
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
// @Param        request body RevokeTokenRequest true "Refresh token to revoke"
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

	var requestBody RevokeTokenRequest
	if err := decodeRequestBody(r, &requestBody); err != nil {
		response.BadRequest().AddTrace(err).WithModule("auth").Send(w)
		return
	}

	if requestBody.Token == "" {
		response.BadRequest().AddTrace("refresh token to be revoked is required").WithModule("auth").Send(w)
		return
	}

	err = h.AuthService.RevokeRefreshToken(user.ID, requestBody.Token)
	if err != nil {
		response.BadRequest().WithMsg("error revoking token").AddTrace(err).WithModule("auth").Send(w)
		return
	}

	response.OK().WithMsg("refresh token revoked successfully").WithModule("auth").Send(w)
}

type VerifyAccountRequest struct {
	Token string `json:"token" example:"123456"`
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

	var requestBody VerifyAccountRequest
	if err := decodeRequestBody(r, &requestBody); err != nil {
		response.BadRequest().AddTrace(err).WithModule("auth").Send(w)
		return
	}

	if requestBody.Token == "" {
		response.BadRequest().WithMsg("verification token is required").WithModule("auth").Send(w)
		return
	}

	err = h.AuthService.VerifyUser(&user, requestBody.Token)
	if err != nil {
		response.BadRequest().WithMsg("error verifying user").AddTrace(err).WithModule("auth").Send(w)
		return
	}

	refreshHeader := r.Header.Get("Refresh")
	refreshTokenString := strings.TrimPrefix(refreshHeader, "Bearer ")
	err = h.AuthService.Logout(user.ID, refreshTokenString)
	if err != nil {
		response.BadRequest().WithMsg("error loggin out").AddTrace(err).WithModule("auth").Send(w)
		return
	}

	access_token, refresh_token, err := h.AuthService.GenerateTokenPair(user, r)
	if err != nil {
		response.BadRequest().WithMsg("error generating token pair").AddTrace(err).WithModule("auth").Send(w)
		return
	}

	w.Header().Set("X-New-Access-Token", access_token)
	w.Header().Set("X-New-Refresh-Token", refresh_token)

	response.OK().WithMsg("account verified").WithModule("auth").Send(w)
}

type ForgotPasswordRequest struct {
	Email string `json:"email"`
}

func (h *AuthHandler) ForgotPassword(w http.ResponseWriter, r *http.Request) {
	var req ForgotPasswordRequest
	if err := decodeRequestBody(r, &req); err != nil {
		response.BadRequest().AddTrace(err).WithModule("auth").Send(w)
		return
	}

	if err := h.AuthService.InitiatePasswordReset(req.Email); err != nil {
		response.BadRequest().WithMsg("error initiating password reset").AddTrace(err).WithModule("auth").Send(w)
		return
	}

	response.OK().WithMsg("password reset email sent").WithModule("auth").Send(w)
}

type ChangePasswordRequest struct {
	NewPassword string `json:"new_password"`
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
		response.BadRequest().WithMsg("missing reset token").WithModule("auth").Send(w)
		return
	}

	var req ChangePasswordRequest
	if err := decodeRequestBody(r, &req); err != nil {
		response.BadRequest().WithMsg("missing reset token").WithModule("auth").Send(w)
		return
	}

	claims := &models.PasswordResetClaims{}
	token, err := jwt.ParseWithClaims(resetToken, claims, func(t *jwt.Token) (interface{}, error) {
		return []byte(secretKey), nil
	})

	if err != nil || !token.Valid || !claims.IsPasswordReset {
		response.BadRequest().WithMsg("invalid or expired reset token").WithModule("auth").Send(w)
		return
	}

	if err := h.AuthService.ChangePassword(claims.UserID, req.NewPassword); err != nil {
		response.BadRequest().WithMsg("error changing password").WithModule("auth").Send(w)
		return
	}

	response.OK().WithMsg("password changed succesfuly").WithModule("auth").Send(w)
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
		response.BadRequest().WithMsg("error resending verification code").AddTrace(err).WithModule("auth").Send(w)
		return
	}

	response.OK().WithMsg("verification code sent").WithModule("auth").Send(w)
}

// type SwitchEventCreatorStatusRequest struct {
// 	Email string `json:"email" example:"user@example.com"`
// }
//
// // SwitchEventCreatorStatus godoc
// // @Summary      Toggle event creator status
// // @Description  Switches a user's event creator status (enables/disables ability to create events). Only available to super users.
// // @Tags         auth
// // @Accept       json
// // @Produce      json
// // @Security     Bearer
// // @Param        Authorization header string true "Bearer {access_token}"
// // @Param        Refresh header string true "Bearer {refresh_token}"
// // @Param        request body SwitchEventCreatorStatusRequest true "Target user email"
// // @Success      200  {object}  NoDataSuccessResponse
// // @Failure      400  {object}  AuthStandardErrorResponse
// // @Failure      401  {object}  AuthStandardErrorResponse
// // @Failure      403  {object}  AuthStandardErrorResponse
// // @Router       /switch-event-creator-status [post]
// func (h *AuthHandler) SwitchEventCreatorStatus(w http.ResponseWriter, r *http.Request) {
// 	user, err := getUserFromContext(h.AuthService.AuthRepo.FindUserByID, r)
// 	if err != nil {
// 		HandleErrMsg("error getting user", err, w).Stack("auth").BadRequest()
// 		return
// 	}

// 	var reqBody SwitchEventCreatorStatusRequest
// 	if err := decodeRequestBody(r, &reqBody); err != nil {
// 		BadRequestError(w, err, "auth")
// 		return
// 	}

// 	if reqBody.Email == "" {
// 		BadRequestError(w, NewErr("email is required"), "auth")
// 		return
// 	}

// 	if err := h.AuthService.SwitchEventCreatorStatus(user, reqBody.Email); err != nil {
// 		if strings.Contains(err.Error(), "only superusers") {
// 			ForbiddenError(w, err, "auth")
// 			return
// 		}
// 		HandleErrMsg("error switching event creator status", err, w).Stack("auth").BadRequest()
// 		return
// 	}

// 	handleSuccess(w, nil, "event creator status switched successfully", http.StatusOK)
// }

// type ChangeUserNameRequest struct {
// 	Name     string `json:"name"`
// 	LastName string `json:"last_name"`
// }

// // ChangeUserName godoc
// // @Summary      Change user name
// // @Description  Updates the authenticated user's first and last name
// // @Tags         auth
// // @Accept       json
// // @Produce      json
// // @Security     Bearer
// // @Param        Authorization header string true "Bearer {access_token}"
// // @Param        Refresh header string true "Bearer {refresh_token}"
// // @Param        request body ChangeUserNameRequest true "New name information"
// // @Success      200  {object}  NoDataSuccessResponse
// // @Failure      400  {object}  AuthStandardErrorResponse
// // @Failure      401  {object}  AuthStandardErrorResponse
// // @Router       /change-name [post]
// func (h *AuthHandler) ChangeUserName(w http.ResponseWriter, r *http.Request) {
// 	user, err := getUserFromContext(h.AuthService.AuthRepo.FindUserByID, r)
// 	if err != nil {
// 		HandleErrMsg("error getting user", err, w).Stack("auth").BadRequest()
// 		return
// 	}

// 	var reqBody ChangeUserNameRequest
// 	if err := decodeRequestBody(r, &reqBody); err != nil {
// 		BadRequestError(w, err, "auth")
// 		return
// 	}

// 	if reqBody.Name == "" {
// 		BadRequestError(w, NewErr("name is required"), "auth")
// 		return
// 	}

// 	if reqBody.LastName == "" {
// 		BadRequestError(w, NewErr("last name is required"), "auth")
// 		return
// 	}

// 	if err := h.AuthService.ChangeUserName(user, reqBody.Name, reqBody.LastName); err != nil {
// 		HandleErrMsg("error changing user name", err, w).Stack("auth").BadRequest()
// 		return
// 	}

// 	handleSuccess(w, nil, "user name changed successfully", http.StatusOK)
// }

type UserResponse struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	LastName       string `json:"last_name"`
	Email          string `json:"email"`
	IsVerified     bool   `json:"is_verified"`
	IsEventCreator bool   `json:"is_event_creator"`
	IsSuperUser    bool   `json:"is_super_user"`
	IsUenf         bool   `json:"is_uenf"`
	UenfSemester   int    `json:"uenf_semester"`
	CreatedAt      string `json:"created_at"`
}

type GetUsersResponse struct {
	Users      []UserResponse `json:"users"`
	Pagination *struct {
		Page       int   `json:"page"`
		Limit      int   `json:"limit"`
		Total      int64 `json:"total"`
		TotalPages int   `json:"total_pages"`
		HasNext    bool  `json:"has_next"`
		HasPrev    bool  `json:"has_prev"`
	} `json:"pagination,omitempty"`
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
			response.NotFound().WithMsg("user not found").AddTrace(err).WithModule("auth").Send(w)
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
			response.BadRequest().WithMsg("error retrieving users").AddTrace(err).WithModule("auth").Send(w)
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

	access, refresh, err := h.AuthService.RefreshTokens(refreshToken, r)
	if err != nil {
		response.Unauthorized().AddTrace(err).WithModule("auth").Send(w)
		return
	}

	response.OK().WithData(map[string]string{"access_token": access, "refresh_token": refresh}).WithModule("auth").Send(w)
}
