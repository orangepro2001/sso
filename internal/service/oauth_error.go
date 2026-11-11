package service

// OAuthError is an OAuth 2.0 / OIDC error (RFC 6749 §5.2, RFC 7009 §2.2.1).
// Its status and body are exactly what the PHP answered: {"error",
// "error_description"} with Cache-Control: no-store.
type OAuthError struct {
	Code        string
	Description string
	Status      int
	ErrorURI    string
}

func (e *OAuthError) Error() string { return e.Code + ": " + e.Description }

func InvalidRequest(description string) *OAuthError {
	return &OAuthError{Code: "invalid_request", Description: description, Status: 400}
}

func InvalidClient(description string) *OAuthError {
	if description == "" {
		description = "Client authentication failed"
	}
	return &OAuthError{Code: "invalid_client", Description: description, Status: 401}
}

func InvalidGrant(description string) *OAuthError {
	return &OAuthError{Code: "invalid_grant", Description: description, Status: 400}
}

func UnauthorizedClient(description string) *OAuthError {
	return &OAuthError{Code: "unauthorized_client", Description: description, Status: 400}
}

func UnsupportedGrantType(description string) *OAuthError {
	return &OAuthError{Code: "unsupported_grant_type", Description: description, Status: 400}
}

func InvalidScope(description string) *OAuthError {
	return &OAuthError{Code: "invalid_scope", Description: description, Status: 400}
}

func AccessDenied(description string) *OAuthError {
	if description == "" {
		description = "The resource owner denied the request"
	}
	return &OAuthError{Code: "access_denied", Description: description, Status: 403}
}

func ServerError(description string) *OAuthError {
	return &OAuthError{Code: "server_error", Description: description, Status: 500}
}
