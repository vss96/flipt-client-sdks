package flipt

import (
	"context"
	"time"
)

// EvaluationRequest represents the request structure for evaluating a flag.
type EvaluationRequest struct {
	FlagKey  string            `json:"flag_key"`
	EntityID string            `json:"entity_id"`
	Context  map[string]string `json:"context"`
}

// clientTokenAuthentication is used for client token authentication.
type clientTokenAuthentication struct {
	Token string `json:"client_token"`
}

// jwtAuthentication is used for JWT authentication.
type jwtAuthentication struct {
	Token string `json:"jwt_token"`
}

// FetchMode determines how the client fetches flag state.
type FetchMode string

const (
	// FetchModeStreaming uses streaming to fetch flag state.
	FetchModeStreaming FetchMode = "streaming"
	// FetchModePolling uses polling to fetch flag state.
	FetchModePolling FetchMode = "polling"
)

// ErrorStrategy determines how the client handles errors when fetching flag state.
type ErrorStrategy string

const (
	// ErrorStrategyFail causes the client to return an error if flag state cannot be fetched.
	ErrorStrategyFail ErrorStrategy = "fail"
	// ErrorStrategyFallback causes the client to use the last known good state if an error occurs.
	ErrorStrategyFallback ErrorStrategy = "fallback"
)

// Flag represents a feature flag.
type Flag struct {
	Key     string `json:"key"`
	Enabled bool   `json:"enabled"`
	Type    string `json:"type"`
}

// VariantEvaluationResponse is the response for a variant flag evaluation.
type VariantEvaluationResponse struct {
	Match                 bool     `json:"match"`
	SegmentKeys           []string `json:"segment_keys"`
	Reason                string   `json:"reason"`
	FlagKey               string   `json:"flag_key"`
	VariantKey            string   `json:"variant_key"`
	VariantAttachment     string   `json:"variant_attachment"`
	RequestDurationMillis float64  `json:"request_duration_millis"`
	Timestamp             string   `json:"timestamp"`
}

// BooleanEvaluationResponse is the response for a boolean flag evaluation.
type BooleanEvaluationResponse struct {
	Enabled               bool     `json:"enabled"`
	FlagKey               string   `json:"flag_key"`
	Reason                string   `json:"reason"`
	RequestDurationMillis float64  `json:"request_duration_millis"`
	Timestamp             string   `json:"timestamp"`
	SegmentKeys           []string `json:"segment_keys"`
}

// ErrorEvaluationResponse is the response for an error during flag evaluation.
type ErrorEvaluationResponse struct {
	FlagKey      string `json:"flag_key"`
	NamespaceKey string `json:"namespace_key"`
	Reason       string `json:"reason"`
}

// BatchEvaluationResponse is the response for a batch flag evaluation.
type BatchEvaluationResponse struct {
	Responses             []*Response `json:"responses"`
	RequestDurationMillis float64     `json:"request_duration_millis"`
}

// Response is a wrapper for different types of evaluation responses.
type Response struct {
	Type                      string                     `json:"type"`
	VariantEvaluationResponse *VariantEvaluationResponse `json:"variant_evaluation_response,omitempty"`
	BooleanEvaluationResponse *BooleanEvaluationResponse `json:"boolean_evaluation_response,omitempty"`
	ErrorEvaluationResponse   *ErrorEvaluationResponse   `json:"error_evaluation_response,omitempty"`
}

// Result is a generic result wrapper for evaluation responses.
type Result[R any] struct {
	Status       string `json:"status"`
	Result       *R     `json:"result,omitempty"`
	ErrorMessage string `json:"error_message,omitempty"`
}

// VariantResult is a result wrapper for VariantEvaluationResponse.
type VariantResult Result[VariantEvaluationResponse]

// BooleanResult is a result wrapper for BooleanEvaluationResponse.
type BooleanResult Result[BooleanEvaluationResponse]

// BatchResult is a result wrapper for BatchEvaluationResponse.
type BatchResult Result[BatchEvaluationResponse]

// ListFlagsResult is a result wrapper for a list of Flag.
type ListFlagsResult Result[[]Flag]

// Hook is an interface for before and after evaluation callbacks.
type Hook interface {
	// Before is called before evaluation with the flag key.
	Before(ctx context.Context, data BeforeHookData)
	// After is called after successful evaluation with evaluation results.
	After(ctx context.Context, data AfterHookData)
}

// BeforeHookData contains the data passed to the Before hook.
type BeforeHookData struct {
	FlagKey string
}

// AfterHookData contains the data passed to the After hook.
type AfterHookData struct {
	FlagKey     string
	FlagType    string
	Value       string
	Reason      string
	SegmentKeys []string
}

// AuthenticationProvider is a function that returns an AuthenticationLease.
// It is called to obtain (and later refresh) authentication credentials.
type AuthenticationProvider func() (*AuthenticationLease, error)

const (
	// defaultMaxAuthRetries is the default maximum number of consecutive
	// authentication refresh failures before the refresh goroutine stops.
	defaultMaxAuthRetries = 5
)

// AuthenticationLease holds an authentication strategy and optional expiry metadata
// for dynamic authentication. Use the NewFixed* or NewExpiring* constructors to create leases.
type AuthenticationLease struct {
	strategy   any        // clientTokenAuthentication or jwtAuthentication
	expiresAt  *time.Time // nil for fixed leases
	maxRetries int
}

// LeaseOption configures optional parameters on an expiring AuthenticationLease.
type LeaseOption func(*AuthenticationLease)

// WithMaxRetries sets the maximum number of consecutive authentication refresh
// failures before the refresh goroutine stops. The default is 5. Panics if n < 0.
func WithMaxRetries(n int) LeaseOption {
	if n < 0 {
		panic("flipt: WithMaxRetries: n must be >= 0")
	}
	return func(l *AuthenticationLease) {
		l.maxRetries = n
	}
}

// NewFixedJWTLease creates a fixed (non-expiring) JWT authentication lease.
func NewFixedJWTLease(token string) *AuthenticationLease {
	return &AuthenticationLease{
		strategy: jwtAuthentication{Token: token},
	}
}

// NewFixedClientTokenLease creates a fixed (non-expiring) client token authentication lease.
func NewFixedClientTokenLease(token string) *AuthenticationLease {
	return &AuthenticationLease{
		strategy: clientTokenAuthentication{Token: token},
	}
}

// NewExpiringJWTLease creates a JWT authentication lease that expires at the given time.
// The client will call the AuthenticationProvider to refresh credentials before expiry.
func NewExpiringJWTLease(token string, expiresAt time.Time, opts ...LeaseOption) *AuthenticationLease {
	t := expiresAt
	l := &AuthenticationLease{
		strategy:   jwtAuthentication{Token: token},
		expiresAt:  &t,
		maxRetries: defaultMaxAuthRetries,
	}
	for _, opt := range opts {
		opt(l)
	}
	return l
}

// NewExpiringClientTokenLease creates a client token authentication lease that expires at the given time.
// The client will call the AuthenticationProvider to refresh credentials before expiry.
func NewExpiringClientTokenLease(token string, expiresAt time.Time, opts ...LeaseOption) *AuthenticationLease {
	t := expiresAt
	l := &AuthenticationLease{
		strategy:   clientTokenAuthentication{Token: token},
		expiresAt:  &t,
		maxRetries: defaultMaxAuthRetries,
	}
	for _, opt := range opts {
		opt(l)
	}
	return l
}

// ExpiresAt returns the expiry time of the lease, or nil if the lease is fixed.
func (l *AuthenticationLease) ExpiresAt() *time.Time {
	return l.expiresAt
}

// MaxRetries returns the maximum number of consecutive refresh failures allowed.
// Returns 0 for fixed leases.
func (l *AuthenticationLease) MaxRetries() int {
	return l.maxRetries
}
