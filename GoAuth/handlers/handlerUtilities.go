package handlers

import (
	"GoAuth/models"
	u "GoAuth/utilities"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// extractSlugAndValidate extracts slug from URL path and validates it's not empty
func extractSlugAndValidate(r *http.Request) (string, error) {
	slug := r.PathValue("slug")
	if slug == "" {
		return "", errors.New("the event slug can't be empty")
	}
	return strings.ToLower(slug), nil
}

// getUserFromContext extracts and returns the user from context based on JWT claims
func getUserFromContext(getUserByID func(string) (models.User, error), r *http.Request) (models.User, error) {
	claims := u.GetUserFromContext(r.Context())
	if claims == nil {
		return models.User{}, errors.New("error getting data from claims")
	}
	user, err := getUserByID(claims.ID)
	if err != nil {
		return models.User{}, errors.New("error getting user: " + err.Error())
	}
	return user, nil
}

// decodeRequestBody decodes the request body into the provided struct
func decodeRequestBody(r *http.Request, target interface{}) error {
	if err := json.NewDecoder(r.Body).Decode(target); err != nil {
		return errors.New("error parsing request body: " + err.Error())
	}
	return nil
}

// DEPRECATED: Use HandleErr instead
// handleError sends a standardized error response using the fluent API
func handleError(w http.ResponseWriter, err error, statusCode int) {
	u.SendError(w, []string{err.Error()}, "event-stack", statusCode)
}

// handleSuccess sends a standardized success response
func handleSuccess(w http.ResponseWriter, data interface{}, message string, statusCode int) {
	u.SendSuccess(w, data, message, statusCode)
}

// Err is a wrapper function that converts a standard error to an ErrorHandler
// This allows for the pattern: Err(err, w).Msg(...).Stack(...).BadRequest()
func Err(e error, w http.ResponseWriter) *u.ErrorHandler {
	if e == nil {
		e = errors.New("unknown error")
	}
	return u.FromError(e, w)
}

// HandleErr is a shorthand function for creating an ErrorHandler with a response writer
// This allows for the pattern: HandleErr(err, w).Stack(...).BadRequest()
func HandleErr(e error, w http.ResponseWriter) *u.ErrorHandler {
	if e == nil {
		e = errors.New("unknown error")
	}
	return u.NewErrorHandler(w, e)
}

// HandleErrMsg creates an ErrorHandler with a custom message directly
// This allows for the pattern: HandleErrMsg("not found", err, w).Stack(...).NotFound()
func HandleErrMsg(msg string, err error, w http.ResponseWriter) *u.ErrorHandler {
	if err == nil {
		return u.Error(msg, w)
	}

	fullMsg := fmt.Sprintf("%s: %s", msg, err.Error())
	return u.Error(fullMsg, w)
}

func NotFoundError(w http.ResponseWriter, err error, resourceType string, stack string) {
	msg := resourceType + " not found"
	if err != nil {
		msg = fmt.Sprintf("%s: %s", msg, err.Error())
	}
	u.Error(msg, w).Stack(stack).NotFound()
}

func BadRequestError(w http.ResponseWriter, err error, stack string) {
	if err == nil {
		err = errors.New("invalid request")
	}
	HandleErr(err, w).Stack(stack).BadRequest()
}

func UnauthorizedError(w http.ResponseWriter, err error, stack string) {
	if err == nil {
		err = errors.New("unauthorized access")
	}
	HandleErr(err, w).Stack(stack).Unauthorized()
}

func ForbiddenError(w http.ResponseWriter, err error, stack string) {
	if err == nil {
		err = errors.New("access forbidden")
	}
	HandleErr(err, w).Stack(stack).Forbidden()
}

func ServerError(w http.ResponseWriter, err error, stack string) {
	if err == nil {
		err = errors.New("internal server error")
	}
	HandleErr(err, w).Msg("Server error").Stack(stack).InternalServerError()
}

// ConflictError returns a pre-configured "conflict" error
func ConflictError(w http.ResponseWriter, err error, resourceType string, stack string) {
	var msg string
	if resourceType != "" {
		msg = resourceType + " already exists"
	} else {
		msg = "Resource conflict"
	}

	if err != nil {
		HandleErr(err, w).Msg(msg).Stack(stack).Conflict()
	} else {
		u.Error(msg, w).Stack(stack).Conflict()
	}
}

func NewErr(msg string) error {
	return errors.New(msg)
}
