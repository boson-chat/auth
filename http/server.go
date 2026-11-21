// Package http wires the service together (constructor DI in one place) and
// runs the public and internal listeners.
package http

import (
	"context"
	"errors"
	"fmt"
	nethttp "net/http"
	"time"

	"github.com/boson-chat/auth/config"
	"github.com/boson-chat/auth/http/handlers"
	"github.com/boson-chat/auth/http/middleware"
	"github.com/boson-chat/auth/internal/db"
	"github.com/boson-chat/auth/internal/db/repositories/accountremoval"
	"github.com/boson-chat/auth/internal/db/repositories/audit"
	"github.com/boson-chat/auth/internal/db/repositories/credential"
	"github.com/boson-chat/auth/internal/db/repositories/emailtoken"
	"github.com/boson-chat/auth/internal/db/repositories/identity"
	"github.com/boson-chat/auth/internal/db/repositories/invite"
	"github.com/boson-chat/auth/internal/db/repositories/refreshtoken"
	"github.com/boson-chat/auth/internal/db/repositories/role"
	"github.com/boson-chat/auth/internal/db/repositories/rolechannel"
	sessionrepo "github.com/boson-chat/auth/internal/db/repositories/session"
	settingsrepo "github.com/boson-chat/auth/internal/db/repositories/settings"
	"github.com/boson-chat/auth/internal/db/repositories/signingkey"
	socialrepo "github.com/boson-chat/auth/internal/db/repositories/social"
	"github.com/boson-chat/auth/internal/db/repositories/ssocode"
	"github.com/boson-chat/auth/internal/db/repositories/user"
	"github.com/boson-chat/auth/internal/logger"
	"github.com/boson-chat/auth/internal/mailer"
	"github.com/boson-chat/auth/internal/password"
	"github.com/boson-chat/auth/internal/services/account"
	"github.com/boson-chat/auth/internal/services/admin"
	auditsvc "github.com/boson-chat/auth/internal/services/audit"
	"github.com/boson-chat/auth/internal/services/authn"
	"github.com/boson-chat/auth/internal/services/branding"
	"github.com/boson-chat/auth/internal/services/email"
	"github.com/boson-chat/auth/internal/services/idp"
	"github.com/boson-chat/auth/internal/services/idp/oidc"
	"github.com/boson-chat/auth/internal/services/idp/saml"
	invitesvc "github.com/boson-chat/auth/internal/services/invite"
	"github.com/boson-chat/auth/internal/services/ircaccounts"
	"github.com/boson-chat/auth/internal/services/keys"
	"github.com/boson-chat/auth/internal/services/rolechannels"
	"github.com/boson-chat/auth/internal/services/roles"
	"github.com/boson-chat/auth/internal/services/session"
	"github.com/boson-chat/auth/internal/services/settings"
	"github.com/boson-chat/auth/internal/services/social"
	"github.com/boson-chat/auth/internal/services/sso"
	"github.com/boson-chat/auth/internal/services/stackconfig"
	"github.com/boson-chat/auth/internal/services/token"
	"github.com/boson-chat/auth/metrics"
)

// Options override dependencies (tests, CLI).
type Options struct {
	Mailer         mailer.Mailer
	Metrics        *metrics.Metrics
	MetricsHandler nethttp.Handler
	Now            func() time.Time
	// SSOHTTPClient is used for calls to identity providers (tests).
	SSOHTTPClient *nethttp.Client
}

// App is the wired service.
type App struct {
	Config   config.Config
	DB       *db.DB
	Public   nethttp.Handler
	Internal nethttp.Handler

	Keys     keys.KeyServiceImpl
	Account  account.AccountServiceImpl
	Admin    admin.AdminServiceImpl
	Sessions session.SessionServiceImpl
	Email    email.EmailServiceImpl
	SSO      sso.SSOServiceImpl
	Settings settings.SettingsServiceImpl
	Roles    roles.RolesServiceImpl
	// IRCAccounts is the removed-accounts feed for IRC.
	IRCAccounts ircaccounts.IRCAccountsServiceImpl
	// StackConfig applies the stack config file (BOSON_CONFIG).
	StackConfig stackconfig.StackConfigServiceImpl
	// Branding is the network theme from the config file's branding: section.
	Branding branding.BrandingServiceImpl
	// Social is friends, blocks, privacy and private calls.
	Social social.SocialServiceImpl
	limits *handlers.Limits
}

// Build constructs everything: database → repositories → services → handlers.
func Build(ctx context.Context, cfg config.Config, opts Options) (*App, error) {
	kek, err := cfg.TokenConfig.DecodeKeyEncryptionKey()
	if err != nil {
		return nil, err
	}
	trusted, err := cfg.HTTPConfig.TrustedProxyPrefixes()
	if err != nil {
		return nil, err
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	m := opts.Metrics
	if m == nil {
		m = metrics.Noop()
	}
	// The SMTP mailer is rebuilt when the config file's smtp keys change;
	// an injected (test) mailer stays as it is.
	var swapMailer *mailer.Swappable
	mail := opts.Mailer
	if mail == nil {
		smtp, err := mailer.New(cfg.SMTPConfig)
		if err != nil {
			return nil, err
		}
		swapMailer = mailer.NewSwappable(smtp)
		mail = swapMailer
	}
	hasher, err := password.NewHasher(password.Params{
		MemoryKiB: cfg.PasswordConfig.MemoryKiB, Iterations: cfg.PasswordConfig.Iterations, Parallelism: cfg.PasswordConfig.Parallelism,
	})
	if err != nil {
		return nil, err
	}

	// 1. Database
	database, err := db.NewDatabase(ctx, cfg.DBConfig)
	if err != nil {
		return nil, err
	}

	// 2. Repositories
	userRepo := user.NewUserRepository(database)
	credRepo := credential.NewCredentialRepository(database)
	sessionRepo := sessionrepo.NewSessionRepository(database)
	refreshRepo := refreshtoken.NewRefreshTokenRepository(database)
	emailTokenRepo := emailtoken.NewEmailTokenRepository(database)
	keyRepo := signingkey.NewSigningKeyRepository(database)
	auditRepo := audit.NewAuditRepository(database)
	inviteRepo := invite.NewInviteRepository(database)
	identityRepo := identity.NewIdentityRepository(database)
	settingsRepo := settingsrepo.NewSettingsRepository(database)
	ssoCodeRepo := ssocode.NewSSOCodeRepository(database)
	roleRepo := role.NewRoleRepository(database)
	removalRepo := accountremoval.NewAccountRemovalRepository(database)
	roleChannelRepo := rolechannel.NewRoleChannelRepository(database)

	// 3. Services
	auditService := auditsvc.NewAuditService(auditRepo)
	rolesService := roles.NewRolesService(roleRepo, userRepo, database, auditService, opts.Now)
	ircAccountsService := ircaccounts.NewIRCAccountsService(removalRepo, opts.Now)
	settingsService := settings.NewSettingsService(settingsRepo, database, auditService, cfg.AccountConfig, opts.Now)
	keyService, err := keys.NewKeyService(keyRepo, database, keys.Options{
		EncryptionKey: kek,
		Rotation:      cfg.TokenConfig.KeyRotation,
		PublishLead:   cfg.TokenConfig.KeyPublishLead,
		MaxTokenTTL:   cfg.TokenConfig.MaxTokenTTL(),
		Now:           opts.Now,
	})
	if err != nil {
		_ = database.Close()
		return nil, err
	}
	tokenService := token.NewTokenService(keyService, token.Options{
		Issuer: cfg.TokenConfig.Issuer, AccessTTL: cfg.TokenConfig.AccessTokenTTL, VoiceTTL: cfg.TokenConfig.VoiceTokenTTL, Now: opts.Now,
	})
	sessionService := session.NewSessionService(sessionRepo, refreshRepo, userRepo, database, auditService, m, session.Options{
		RefreshTTL: cfg.TokenConfig.RefreshTokenTTL, SessionMaxAge: cfg.TokenConfig.SessionMaxAge, Now: opts.Now,
	})
	brandingService := branding.NewBrandingService(cfg.HTTPConfig.PublicURL)
	emailService := email.NewEmailService(mail, m, email.Options{
		AppURL: cfg.HTTPConfig.AppURL, SiteName: cfg.AppConfig.SiteName, From: cfg.SMTPConfig.From, Logo: func() email.Logo {
			l := brandingService.EmailLogo()
			return email.Logo{URL: l.URL, Width: l.Width, Height: l.Height}
		},
		VerifyTTL: cfg.AccountConfig.EmailVerifyTTL, ResetTTL: cfg.AccountConfig.PasswordResetTTL,
		SetupTTL: cfg.AccountConfig.AccountSetupTTL, InviteTTL: 7 * 24 * time.Hour, Audit: auditService,
	})
	inviteService := invitesvc.NewInviteService(inviteRepo, opts.Now)
	accountService := account.NewAccountService(account.Deps{
		Users: userRepo, Credentials: credRepo, EmailTokens: emailTokenRepo, Roles: roleRepo, Tx: database,
		Invites: inviteService, Sessions: sessionService, Email: emailService, Audit: auditService,
		Settings: settingsService, Hasher: hasher, Metrics: m, Config: cfg.AccountConfig, Now: opts.Now,
	})
	authnService := authn.NewAuthnService(authn.Deps{
		Users: userRepo, Credentials: credRepo, Sessions: sessionService, Tokens: tokenService,
		Audit: auditService, Hasher: hasher, Metrics: m, Settings: settingsService, Roles: rolesService,
	})
	adminService := admin.NewAdminService(accountService, userRepo, database, sessionService, inviteService, auditService, rolesService, opts.Now)
	ssoClient := opts.SSOHTTPClient
	if ssoClient == nil {
		ssoClient = &nethttp.Client{Timeout: cfg.SSOConfig.HTTPTimeout}
	}
	registry := idp.NewRegistry()
	registry.RegisterKind(identity.KindOIDC, oidc.Kind{HTTPClient: ssoClient, AllowHTTP: cfg.SSOConfig.AllowHTTP})
	registry.RegisterKind(identity.KindSAML, saml.Kind{HTTPClient: ssoClient, AllowHTTP: cfg.SSOConfig.AllowHTTP})
	returnTo, err := sso.NewReturnToPolicy(cfg.HTTPConfig.AppURL,
		append([]string{cfg.HTTPConfig.AppURL, cfg.HTTPConfig.PublicURL}, config.SplitList(cfg.HTTPConfig.CORSAllowedOrigins)...),
		config.SplitList(cfg.SSOConfig.ReturnToAllowed))
	if err != nil {
		_ = database.Close()
		return nil, err
	}
	ssoService, err := sso.NewSSOService(sso.Deps{
		Identities: identityRepo, Codes: ssoCodeRepo, Users: userRepo, Credentials: credRepo, Tx: database,
		Registry: registry, Invites: inviteService, Settings: settingsService, Authn: authnService,
		Audit: auditService, Metrics: m, ReturnTo: returnTo, EncryptionKey: kek,
		PublicURL: cfg.HTTPConfig.PublicURL, StateTTL: cfg.SSOConfig.StateTTL, CodeTTL: cfg.SSOConfig.CodeTTL, Now: opts.Now,
	})
	if err != nil {
		_ = database.Close()
		return nil, err
	}
	if err := ssoService.Reload(ctx); err != nil {
		logger.FromCtx(ctx).Warn().Err(err).Msg("loading identity providers")
	}
	stackConfig := stackconfig.NewStackConfigService(stackconfig.Deps{
		Env: cfg, Settings: settingsService, Email: emailService, Branding: brandingService, Mailer: swapMailer, ReturnTo: returnTo,
		Audit: auditService, Now: opts.Now,
	})
	if err := stackConfig.Load(ctx); err != nil {
		_ = database.Close()
		return nil, fmt.Errorf("config file %s: %w", cfg.AppConfig.ConfigFile, err)
	}

	roleChannelsService := rolechannels.NewRoleChannelsService(rolechannels.Deps{
		Channels: roleChannelRepo, Roles: roleRepo, Users: userRepo, Access: rolesService.Access, Tx: database, Audit: auditService,
		Settings: func() rolechannels.Settings {
			eff := stackConfig.Effective()
			rc, irc := eff.RolesConfig, eff.IRCConfig
			return rolechannels.Settings{Autojoin: rc.ChannelsAutojoin, Rejoin: rc.ChannelsRejoin, Network: rolechannels.NetworkSettings{
				Channels: irc.Channels, Founder: irc.ChannelFounder, AutojoinGuests: irc.AutojoinGuests,
			}}
		},
		Now: opts.Now,
	})

	socialService := social.NewSocialService(social.Deps{
		Repo: socialrepo.NewSocialRepository(database), Users: userRepo, Tx: database,
		Ergo:      social.NewErgoChannels(cfg.SocialConfig.ErgoAPIURL, cfg.SocialConfig.ErgoAPIToken),
		MintToken: authnService.CallVoiceToken, Now: opts.Now, PollWait: cfg.SocialConfig.EventsPollWait,
	})

	// 4. Handlers
	limits := handlers.NewLimits(cfg.RateLimitConfig, m)
	h := &handlers.Handlers{
		Account: accountService, Authn: authnService, Sessions: sessionService, Admin: adminService,
		Keys: keyService, SSO: ssoService, Settings: settingsService, Roles: rolesService, IRCAccounts: ircAccountsService,
		RoleChannels: roleChannelsService, Social: socialService, Branding: brandingService, Email: emailService, Limits: limits, Config: cfg, ConfigStatus: stackConfig.Status,
		FilesURL:        func() string { return stackConfig.Effective().FilesConfig.URL() },
		NetworkChannels: func() []config.NetworkChannel { return stackConfig.Effective().IRCConfig.Channels },
		Ready: func(ctx context.Context) error {
			s, err := database.SQL()
			if err != nil {
				return err
			}
			return s.PingContext(ctx)
		},
	}
	publicMux := nethttp.NewServeMux()
	h.RegisterPublic(publicMux)
	internalMux := nethttp.NewServeMux()
	h.RegisterInternal(internalMux, opts.MetricsHandler)

	return &App{
		Config: cfg,
		DB:     database,
		Public: middleware.Chain(publicMux,
			middleware.Recover, middleware.ClientIP(trusted), middleware.Logging,
			middleware.SecurityHeaders,
			// The branding is public: any origin, no credentials.
			middleware.PublicCORS(middleware.PathPrefix(branding.DocumentPath), middleware.DynamicCORS(stackConfig.CORSOrigins))),
		Internal: middleware.Chain(internalMux,
			middleware.Recover, middleware.ClientIP(nil), middleware.Logging, middleware.SecurityHeaders),
		Keys: keyService, Account: accountService, Admin: adminService, Sessions: sessionService,
		Email: emailService, SSO: ssoService, Settings: settingsService, Roles: rolesService,
		IRCAccounts: ircAccountsService, StackConfig: stackConfig, Branding: brandingService, Social: socialService, limits: limits,
	}, nil
}

// RunBackground starts key maintenance, rate-limiter pruning and cleanup.
func (a *App) RunBackground(ctx context.Context) {
	go a.Keys.Run(ctx, time.Minute)
	go a.StackConfig.Run(ctx)
	go a.Social.Run(ctx)
	a.limits.RunPruner(ctx)
	// Pick up provider changes made on other replicas.
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if err := a.SSO.Reload(ctx); err != nil && ctx.Err() == nil {
					logger.FromCtx(ctx).Warn().Err(err).Msg("reloading identity providers")
				}
			}
		}
	}()
	go func() {
		t := time.NewTicker(time.Hour)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if err := a.Sessions.Cleanup(ctx); err != nil && ctx.Err() == nil {
					logger.FromCtx(ctx).Warn().Err(err).Msg("session cleanup")
				}
				if err := a.Account.Cleanup(ctx); err != nil && ctx.Err() == nil {
					logger.FromCtx(ctx).Warn().Err(err).Msg("email token cleanup")
				}
				if err := a.SSO.Cleanup(ctx); err != nil && ctx.Err() == nil {
					logger.FromCtx(ctx).Warn().Err(err).Msg("sso code cleanup")
				}
				if err := a.IRCAccounts.Cleanup(ctx); err != nil && ctx.Err() == nil {
					logger.FromCtx(ctx).Warn().Err(err).Msg("irc account removals cleanup")
				}
			}
		}
	}()
}

// Close waits for queued emails and closes the database.
func (a *App) Close() error {
	a.Email.Wait()
	return a.DB.Close()
}

// Serve runs both listeners until ctx is done, then shuts down gracefully.
func Serve(ctx context.Context, app *App) error {
	cfg := app.Config.HTTPConfig
	servers := []*nethttp.Server{
		{Addr: cfg.Addr, Handler: app.Public, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 120 * time.Second},
		{Addr: cfg.InternalAddr, Handler: app.Internal, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second},
	}
	errCh := make(chan error, len(servers))
	for i, srv := range servers {
		name := []string{"public", "internal"}[i]
		go func() {
			logger.FromCtx(ctx).Info().Str("addr", srv.Addr).Str("listener", name).Msg("listening")
			if err := srv.ListenAndServe(); err != nil && !errors.Is(err, nethttp.ErrServerClosed) {
				errCh <- fmt.Errorf("%s listener: %w", name, err)
			}
		}()
	}
	var runErr error
	select {
	case <-ctx.Done():
	case runErr = <-errCh:
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	for _, srv := range servers {
		_ = srv.Shutdown(shutdownCtx)
	}
	return runErr
}
