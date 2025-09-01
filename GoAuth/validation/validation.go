package validation

import (
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"unicode"

	"github.com/MintzyG/GoResponse/response"
	"github.com/go-playground/validator/v10"
)

var validate = validator.New()

// PasswordValidationResult holds detailed password validation info
type PasswordValidationResult struct {
	HasUpper  bool
	HasNumber bool
	HasSymbol bool
	IsValid   bool
}

// Global variable to store the last password validation result
var lastPasswordValidation PasswordValidationResult

// Custom password validation - requires uppercase, number, and symbol
func passwordValidator(fl validator.FieldLevel) bool {
	password := fl.Field().String()

	var hasUpper, hasNumber, hasSymbol bool
	for _, c := range password {
		switch {
		case unicode.IsUpper(c):
			hasUpper = true
		case unicode.IsNumber(c):
			hasNumber = true
		case unicode.IsPunct(c) || unicode.IsSymbol(c):
			hasSymbol = true
		}
	}

	isValid := hasUpper && hasNumber && hasSymbol

	// Store the validation result for detailed error reporting
	lastPasswordValidation = PasswordValidationResult{
		HasUpper:  hasUpper,
		HasNumber: hasNumber,
		HasSymbol: hasSymbol,
		IsValid:   isValid,
	}

	return isValid
}

// Custom email domain validation (example of extending validation)
func emailDomainValidator(fl validator.FieldLevel) bool {
	email := fl.Field().String()
	// Add your custom domain logic here
	// For example, only allow certain domains
	allowedDomains := []string{"gmail.com", "yahoo.com", "company.com"}

	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return false
	}

	domain := parts[1]
	for _, allowed := range allowedDomains {
		if domain == allowed {
			return true
		}
	}
	return len(allowedDomains) == 0 // If no restrictions, allow all
}

// Helper function to check if a field is a password field
func isPasswordField(fieldName, structFieldName string) bool {
	fieldLower := strings.ToLower(fieldName)
	structFieldLower := strings.ToLower(structFieldName)

	passwordWords := []string{"password", "passwd", "pwd", "pass"}

	for _, word := range passwordWords {
		if fieldLower == word || structFieldLower == word ||
			strings.Contains(fieldLower, word) || strings.Contains(structFieldLower, word) {
			return true
		}
	}
	return false
}

func init() {
	// Register custom validators
	_ = validate.RegisterValidation("passwd", passwordValidator)
	_ = validate.RegisterValidation("email_domain", emailDomainValidator)

	// Use JSON field names instead of struct field names for better API responses
	validate.RegisterTagNameFunc(func(fld reflect.StructField) string {
		name := strings.SplitN(fld.Tag.Get("json"), ",", 2)[0]
		if name == "-" {
			return ""
		}
		if name == "" {
			return fld.Name
		}
		return name
	})
}

// ValidateStruct validates any struct and returns a Response with validation errors
// If validation passes, returns nil
// If validation fails, returns a BadRequest Response with ValidationTrace errors
func ValidateStruct(s interface{}) *response.Response {
	err := validate.Struct(s)
	if err == nil {
		return nil // Validation passed
	}

	validationErrors := make([]response.ValidationTrace, 0)

	for _, err := range err.(validator.ValidationErrors) {
		structFieldName := err.StructField() // Get the original struct field name
		fieldName := structFieldName         // Default to struct field name
		var msg string
		var value interface{}

		// Always try to get the JSON field name first
		structType := reflect.TypeOf(s)
		if structType.Kind() == reflect.Ptr {
			structType = structType.Elem()
		}
		if structField, ok := structType.FieldByName(structFieldName); ok {
			if jsonTag := structField.Tag.Get("json"); jsonTag != "" {
				jsonFieldName := strings.SplitN(jsonTag, ",", 2)[0]
				if jsonFieldName != "-" && jsonFieldName != "" {
					fieldName = jsonFieldName // Use JSON field name
				}
			}
		}

		// Check if this is a password field using both JSON field name and struct field name
		isPassword := isPasswordField(fieldName, structFieldName)

		// Get the actual field value for better error reporting (but not for password fields)
		if err.Value() != nil && !isPassword {
			value = err.Value()
		}

		// Create user-friendly error messages
		switch err.Tag() {
		case "required":
			msg = "is required"
		case "email":
			msg = "must be a valid email address"
		case "min":
			if err.Kind().String() == "string" {
				msg = fmt.Sprintf("must be at least %s characters long", err.Param())
			} else {
				msg = fmt.Sprintf("must be at least %s", err.Param())
			}

			// If this is a password field, also add detailed password validation errors
			if isPassword {
				// Run password validation to get detailed results
				password := err.Value().(string)
				var hasUpper, hasNumber, hasSymbol bool
				for _, c := range password {
					switch {
					case unicode.IsUpper(c):
						hasUpper = true
					case unicode.IsNumber(c):
						hasNumber = true
					case unicode.IsPunct(c) || unicode.IsSymbol(c):
						hasSymbol = true
					}
				}

				// Add specific password errors as separate validation traces
				if !hasUpper {
					validationErrors = append(validationErrors, response.ValidationTrace{
						Field:   fieldName,
						Message: "must contain at least one uppercase letter",
						Value:   nil,
					})
				}
				if !hasNumber {
					validationErrors = append(validationErrors, response.ValidationTrace{
						Field:   fieldName,
						Message: "must contain at least one number",
						Value:   nil,
					})
				}
				if !hasSymbol {
					validationErrors = append(validationErrors, response.ValidationTrace{
						Field:   fieldName,
						Message: "must contain at least one symbol or punctuation",
						Value:   nil,
					})
				}
			}
		case "max":
			if err.Kind().String() == "string" {
				msg = fmt.Sprintf("must be at most %s characters long", err.Param())
			} else {
				msg = fmt.Sprintf("must be at most %s", err.Param())
			}
		case "len":
			msg = fmt.Sprintf("must be exactly %s characters long", err.Param())
		case "passwd":
			// Add detailed password validation errors to the main validation response
			msg = "password requirements not met"

			// Add specific password errors as separate validation traces
			if !lastPasswordValidation.HasUpper {
				validationErrors = append(validationErrors, response.ValidationTrace{
					Field:   fieldName,
					Message: "must contain at least one uppercase letter",
					Value:   nil, // Don't expose password value
				})
			}
			if !lastPasswordValidation.HasNumber {
				validationErrors = append(validationErrors, response.ValidationTrace{
					Field:   fieldName,
					Message: "must contain at least one number",
					Value:   nil, // Don't expose password value
				})
			}
			if !lastPasswordValidation.HasSymbol {
				validationErrors = append(validationErrors, response.ValidationTrace{
					Field:   fieldName,
					Message: "must contain at least one symbol or punctuation",
					Value:   nil, // Don't expose password value
				})
			}

			// Skip adding the main error since we added specific ones
			continue
		case "email_domain":
			msg = "email domain is not allowed"
		case "oneof":
			msg = fmt.Sprintf("must be one of: %s", strings.ReplaceAll(err.Param(), " ", ", "))
		case "uuid":
			msg = "must be a valid UUID"
		case "numeric":
			msg = "must be numeric"
		case "alpha":
			msg = "must contain only letters"
		case "alphanum":
			msg = "must contain only letters and numbers"
		case "url":
			msg = "must be a valid URL"
		case "uri":
			msg = "must be a valid URI"
		case "hexadecimal":
			msg = "must be a valid hexadecimal"
		case "hexcolor":
			msg = "must be a valid hex color"
		case "rgb":
			msg = "must be a valid RGB color"
		case "rgba":
			msg = "must be a valid RGBA color"
		case "hsl":
			msg = "must be a valid HSL color"
		case "hsla":
			msg = "must be a valid HSLA color"
		case "json":
			msg = "must be valid JSON"
		case "jwt":
			msg = "must be a valid JWT token"
		case "latitude":
			msg = "must be a valid latitude"
		case "longitude":
			msg = "must be a valid longitude"
		case "ssn":
			msg = "must be a valid social security number"
		case "credit_card":
			msg = "must be a valid credit card number"
		case "isbn":
			msg = "must be a valid ISBN"
		case "isbn10":
			msg = "must be a valid ISBN-10"
		case "isbn13":
			msg = "must be a valid ISBN-13"
		case "btc_addr":
			msg = "must be a valid Bitcoin address"
		case "btc_addr_bech32":
			msg = "must be a valid Bitcoin Bech32 address"
		case "eth_addr":
			msg = "must be a valid Ethereum address"
		case "contains":
			msg = fmt.Sprintf("must contain '%s'", err.Param())
		case "containsany":
			msg = fmt.Sprintf("must contain at least one of these characters: %s", err.Param())
		case "excludes":
			msg = fmt.Sprintf("must not contain '%s'", err.Param())
		case "excludesall":
			msg = fmt.Sprintf("must not contain any of these characters: %s", err.Param())
		case "startswith":
			msg = fmt.Sprintf("must start with '%s'", err.Param())
		case "endswith":
			msg = fmt.Sprintf("must end with '%s'", err.Param())
		default:
			msg = fmt.Sprintf("failed %s validation", err.Tag())
		}

		// Add the validation error
		if isPassword {
			validationErrors = append(validationErrors, response.ValidationTrace{
				Field:   fieldName,
				Message: msg,
				Value:   nil,
			})
		} else {
			validationErrors = append(validationErrors, response.ValidationTrace{
				Field:   fieldName,
				Message: msg,
				Value:   value,
			})
		}
	}

	return response.AddValidationErrors(validationErrors...)
}

func Validate[T any](r *http.Request) (T, *response.Response) {
	var zero T
	var data T

	// Check content type
	contentType := r.Header.Get("Content-Type")
	if contentType != "application/json" {
		return zero, response.BadRequest("Content-Type must be application/json").
			WithModule("validation")
	}

	// Decode JSON
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		return zero, response.BadRequest("Invalid JSON format").
			WithModule("validation").
			WithTracePrefix("decode")
	}

	// Validate the struct
	if validationResp := ValidateStruct(data); validationResp != nil {
		return zero, validationResp.WithModule("validation")
	}

	return data, nil
}

// ValidateWith is an alternative that takes a pointer to populate
// Usage: resp := validation.ValidateWith(r, &user)
func ValidateWith[T any](r *http.Request, target *T) *response.Response {
	// Check content type
	contentType := r.Header.Get("Content-Type")
	if contentType != "application/json" {
		return response.BadRequest("Content-Type must be application/json").
			WithModule("validation")
	}

	// Decode JSON
	if err := json.NewDecoder(r.Body).Decode(target); err != nil {
		return response.BadRequest("Invalid JSON format").
			WithModule("validation").
			WithTracePrefix("decode")
	}

	// Validate the struct
	if validationResp := ValidateStruct(*target); validationResp != nil {
		return validationResp.WithModule("validation")
	}

	return nil
}
