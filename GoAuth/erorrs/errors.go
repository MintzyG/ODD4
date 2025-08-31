package response

import "errors"

var (
	ErrContext           = errors.New("couldn't find user in context")
	ErrValidationFailed  = errors.New("validation failed")
	ErrSizeLimitExceeded = errors.New("size limit exceeded")
	ErrEncodingFailed    = errors.New("encoding failed")
	ErrTraceFailed       = errors.New("trace error")
	ErrInterceptorFailed = errors.New("interceptor error")
)
