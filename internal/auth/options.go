package auth

type Options struct {
	// AuthType represents the type of authentication used.
	AuthType string
	// Audience overrides the default audience/scope used to retrieve the source token when supported.
	Audience string
	// TokenFile is the path of the service account token file used by the kubernetes auth source. Defaults to DefaultServiceAccountTokenFile when empty.
	TokenFile string
	// PrintSourceToken is a boolean flag that determines whether the source token should be printed to the console. This is to be used for debugging purposes only as it may expose sensitive information.
	PrintSourceToken bool
}
