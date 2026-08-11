package authx

import (
	"time"

	"github.com/lcylpzls/authx/internal/core"
)

const (
	CodePasswordHashInvalid   = core.CodePasswordHashInvalid
	CodePasswordMismatch      = core.CodePasswordMismatch
	CodePasswordTooLong       = core.CodePasswordTooLong
	CodePasswordTooShort      = core.CodePasswordTooShort
	CodePasswordConfigInvalid = core.CodePasswordConfigInvalid
	CodePasswordInternal      = core.CodePasswordInternal
	CodeTokenInvalid          = core.CodeTokenInvalid
	CodeTokenExpired          = core.CodeTokenExpired
	CodeTokenSignature        = core.CodeTokenSignature
	CodeTokenRevoked          = core.CodeTokenRevoked
	CodeTokenConfigInvalid    = core.CodeTokenConfigInvalid
	CodeRefreshTokenInvalid   = core.CodeRefreshTokenInvalid
	CodeStoreInvalid          = core.CodeStoreInvalid
	CodeForbidden             = core.CodeForbidden
	CodeRBACRoleNotFound      = core.CodeRBACRoleNotFound
	CodeRBACRoleExists        = core.CodeRBACRoleExists
	CodeRBACCycle             = core.CodeRBACCycle
	CodeRBACInvalid           = core.CodeRBACInvalid
	CodeCSRFMismatch          = core.CodeCSRFMismatch
	CodeSessionNotFound       = core.CodeSessionNotFound
	CodeSessionInvalid        = core.CodeSessionInvalid
	CodeSessionStoreInvalid   = core.CodeSessionStoreInvalid
	CodeMFAInvalid            = core.CodeMFAInvalid
	CodeMFAConfigInvalid      = core.CodeMFAConfigInvalid
	CodeOAuth2Invalid         = core.CodeOAuth2Invalid
	CodeOAuth2ConfigInvalid   = core.CodeOAuth2ConfigInvalid
	CodeSecurityConfigInvalid = core.CodeSecurityConfigInvalid
	CodeStoreFull             = core.CodeStoreFull
	CodeRBACLimit             = core.CodeRBACLimit
	CodeCSRFGenerationFailed  = core.CodeCSRFGenerationFailed
	CodePasswordTooWeak       = core.CodePasswordTooWeak
	CodeTokenMissing          = core.CodeTokenMissing
	CodeAuditQueueFull        = core.CodeAuditQueueFull
)

var (
	ErrPasswordHashInvalid   = core.ErrPasswordHashInvalid
	ErrPasswordMismatch      = core.ErrPasswordMismatch
	ErrPasswordTooLong       = core.ErrPasswordTooLong
	ErrPasswordTooShort      = core.ErrPasswordTooShort
	ErrTokenInvalid          = core.ErrTokenInvalid
	ErrTokenExpired          = core.ErrTokenExpired
	ErrTokenSignature        = core.ErrTokenSignature
	ErrTokenRevoked          = core.ErrTokenRevoked
	ErrRefreshTokenInvalid   = core.ErrRefreshTokenInvalid
	ErrForbidden             = core.ErrForbidden
	ErrRoleNotFound          = core.ErrRoleNotFound
	ErrRoleExists            = core.ErrRoleExists
	ErrCycle                 = core.ErrCycle
	ErrRBACInvalid           = core.ErrRBACInvalid
	ErrCSRFMismatch          = core.ErrCSRFMismatch
	ErrSessionNotFound       = core.ErrSessionNotFound
	ErrSessionInvalid        = core.ErrSessionInvalid
	ErrSessionStoreInvalid   = core.ErrSessionStoreInvalid
	ErrMFAInvalid            = core.ErrMFAInvalid
	ErrMFAConfigInvalid      = core.ErrMFAConfigInvalid
	ErrOAuth2Invalid         = core.ErrOAuth2Invalid
	ErrOAuth2ConfigInvalid   = core.ErrOAuth2ConfigInvalid
	ErrSecurityConfigInvalid = core.ErrSecurityConfigInvalid
	ErrStoreFull             = core.ErrStoreFull
	ErrRBACLimit             = core.ErrRBACLimit
	ErrCSRFGenerationFailed  = core.ErrCSRFGenerationFailed
	ErrPasswordTooWeak       = core.ErrPasswordTooWeak
	ErrTokenMissing          = core.ErrTokenMissing
	ErrAuditQueueFull        = core.ErrAuditQueueFull
)

type (
	PasswordConfig = core.PasswordConfig
	CleanupHandle  = core.CleanupHandle
	AuthEvent      = core.AuthEvent
	EventHook      = core.EventHook
	TraceAttr      = core.TraceAttr
	TraceHook      = core.TraceHook
)

func DefaultPasswordConfig() PasswordConfig { return core.DefaultPasswordConfig() }
func StartCleanup(interval time.Duration, fn func() int) *CleanupHandle {
	return core.StartCleanup(interval, fn)
}
