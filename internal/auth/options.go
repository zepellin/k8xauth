package auth

type Options struct {
	// AuthType represents the type of authentication used.
	AuthType string
	// Audience overrides the default audience/scope used to retrieve the source token when supported.
	Audience string
	// PrintSourceToken is a boolean flag that determines whether the source token should be printed to the console. This is to be used for debugging purposes only as it may expose sensitive information.
	PrintSourceToken bool
}
