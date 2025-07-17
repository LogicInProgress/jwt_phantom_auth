# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial release of JWT Phantom Auth gem
- JWT-based authentication with phantom token technique
- Redis integration for token storage
- Rails middleware for automatic authentication
- Comprehensive configuration options
- Error handling with custom exceptions
- Token management (generate, refresh, revoke)
- Phantom token exchange mechanism
- User authentication utilities
- **Multi-model support** for authenticating different user types
- **Model registry** for managing multiple models with different configurations
- **Backward compatibility** with existing single-model configurations

### Features
- **TokenManager**: Handles JWT token generation, validation, and refresh
- **PhantomTokenManager**: Manages phantom tokens for enhanced security
- **UserAuthenticator**: Provides user authentication and validation
- **Middleware**: Rails middleware for automatic request authentication
- **Configuration**: Flexible configuration system with sensible defaults
- **ModelRegistry**: Manages multiple models with different configurations
- **Multi-Model Support**: Authenticate users, admins, customers, and other user types

### Security
- Phantom token technique implementation
- Short-lived access tokens (15 minutes default)
- Long-lived refresh tokens (7 days default)
- Token revocation capabilities
- Secure token storage in Redis

## [1.0.0] - 2024-01-XX

### Added
- Initial release
- Core JWT authentication functionality
- Phantom token support
- Redis integration
- Rails middleware
- Comprehensive configuration system
- Error handling
- API documentation
- Sample Rails application 