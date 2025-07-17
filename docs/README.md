# JWT Phantom Auth Documentation

Welcome to the JWT Phantom Auth documentation! This gem provides a comprehensive JWT-based authentication solution with phantom token technique for enhanced security.

## Documentation Overview

### 📖 [Main README](../README.md)
The main README provides a quick start guide, installation instructions, and basic usage examples. Start here if you're new to the gem.

### 🔧 [API Documentation](API.md)
Comprehensive API reference for all classes, methods, and configuration options. Use this as your reference guide.

### 🛡️ [Security Documentation](SECURITY.md)
Detailed security features, best practices, and considerations for using the gem securely.

### 💡 [Examples and Use Cases](EXAMPLES.md)
Practical examples, code samples, and real-world use cases for integrating the gem into your application.

## Quick Navigation

### Getting Started
- [Installation](../README.md#installation)
- [Quick Start](../README.md#quick-start)
- [Configuration](../README.md#configuration-options)

### Core Features
- [JWT Authentication](../README.md#jwt-based-authentication)
- [Phantom Token Technique](../README.md#phantom-token-technique)
- [Refresh Token Support](../README.md#refresh-token-support)
- [Redis Integration](../README.md#redis-integration)

### API Reference
- [TokenManager](API.md#tokenmanager)
- [PhantomTokenManager](API.md#phantomtokenmanager)
- [UserAuthenticator](API.md#userauthenticator)
- [Middleware](API.md#middleware)
- [Configuration](API.md#configuration)

### Security
- [Security Features](SECURITY.md#security-features)
- [Best Practices](SECURITY.md#best-practices)
- [Threat Model](SECURITY.md#threat-model)
- [Compliance](SECURITY.md#compliance)

### Examples
- [Basic Setup](EXAMPLES.md#basic-setup)
- [Authentication Flow](EXAMPLES.md#authentication-flow)
- [API Integration](EXAMPLES.md#api-integration)
- [Testing](EXAMPLES.md#testing)

## Key Concepts

### Phantom Token Technique
The phantom token technique enhances security by using short-lived, opaque tokens for API access that are exchanged for JWT access tokens when needed. This reduces the exposure of sensitive JWT tokens.

### Token Types
- **Access Tokens**: Short-lived JWT tokens for API authorization (15 minutes default)
- **Refresh Tokens**: Long-lived tokens for obtaining new access tokens (7 days default)
- **Phantom Tokens**: Very short-lived opaque tokens for API access (5 minutes default)

### Security Features
- Cryptographic token signing with HMAC-SHA256
- Token expiration and automatic validation
- Token revocation through Redis blacklisting
- Phantom token technique for reduced token exposure
- Configurable security settings

## Getting Help

### Common Issues
1. **Configuration Errors**: Ensure all required configuration options are set
2. **Redis Connection**: Verify Redis is running and accessible
3. **Token Expiration**: Check token expiry settings
4. **Middleware Issues**: Ensure middleware is properly configured

### Support
- Check the [examples](EXAMPLES.md) for common use cases
- Review the [API documentation](API.md) for method details
- Consult the [security documentation](SECURITY.md) for best practices

## Version Information

- **Current Version**: 1.0.0
- **Ruby Version**: >= 3.1.0
- **Rails Version**: Compatible with Rails 6.0+
- **Dependencies**: JWT, bcrypt, redis

## License

This gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT). 