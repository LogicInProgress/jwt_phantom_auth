# Security Documentation

This document outlines the security features, best practices, and considerations for the JWT Phantom Auth gem.

## Table of Contents

- [Security Features](#security-features)
- [Phantom Token Technique](#phantom-token-technique)
- [Token Security](#token-security)
- [Redis Security](#redis-security)
- [Best Practices](#best-practices)
- [Security Considerations](#security-considerations)
- [Threat Model](#threat-model)

## Security Features

### 1. JWT-based Authentication
- **Cryptographic Signing**: All tokens are cryptographically signed using HMAC-SHA256
- **Token Validation**: Comprehensive token validation including signature verification
- **Expiration Handling**: Automatic token expiration with configurable timeouts
- **Token Revocation**: Support for token revocation through Redis blacklisting

### 2. Phantom Token Technique
- **Short-lived Tokens**: Phantom tokens have very short lifespans (5 minutes default)
- **Opaque Tokens**: Phantom tokens are opaque and don't contain sensitive information
- **Exchange Mechanism**: Secure exchange of phantom tokens for JWT access tokens
- **Reduced Exposure**: Sensitive JWT tokens are only exposed when actively used

### 3. Refresh Token Security
- **Long-lived Refresh Tokens**: Secure refresh tokens with extended lifespans
- **Token Rotation**: Automatic refresh token rotation on each use
- **Revocation Support**: Ability to revoke individual or all refresh tokens
- **Blacklisting**: Revoked tokens are blacklisted in Redis

### 4. Redis Integration
- **Secure Storage**: Token storage in Redis with configurable security
- **Connection Security**: Support for Redis authentication and SSL
- **Data Isolation**: Token data isolation through prefixes and namespacing

## Phantom Token Technique

The phantom token technique is a security enhancement that reduces the exposure of sensitive JWT tokens.

### How It Works

1. **Initial Authentication**: User authenticates and receives a phantom token
2. **API Requests**: Client uses phantom token in Authorization header
3. **Token Exchange**: Middleware exchanges phantom token for JWT access token
4. **Authorization**: JWT token is used for authorization decisions
5. **Token Revocation**: Phantom token is revoked after exchange

### Security Benefits

- **Reduced Token Exposure**: JWT tokens are only exposed during active API calls
- **Short Lifespan**: Phantom tokens have very short lifespans (5 minutes)
- **Opaque Nature**: Phantom tokens don't contain sensitive user information
- **Immediate Revocation**: Phantom tokens are revoked immediately after use

### Implementation Details

```ruby
# Phantom token generation
phantom_token = JwtPhantomAuth.phantom_token_manager.generate_phantom_token(user)

# Phantom token exchange
result = JwtPhantomAuth.phantom_token_manager.exchange_phantom_token(phantom_token)
access_token = result[:access_token]
```

## Token Security

### Access Token Security

- **Short Lifespan**: 15 minutes default (configurable)
- **Minimal Claims**: Only essential user information included
- **Automatic Expiration**: Tokens automatically expire and become invalid
- **Signature Verification**: All tokens are cryptographically signed

### Refresh Token Security

- **Long Lifespan**: 7 days default (configurable)
- **Token Rotation**: New refresh token generated on each use
- **Revocation Support**: Can be revoked individually or in bulk
- **Blacklisting**: Revoked tokens are stored in Redis blacklist

### Token Payload Security

Access tokens contain minimal, necessary information:

```json
{
  "user_id": 123,
  "email": "user@example.com",
  "role": "user",
  "token_type": "access",
  "jti": "unique_token_id",
  "iat": 1640995200,
  "exp": 1640996100,
  "iss": "jwt_phantom_auth",
  "aud": "api"
}
```

### Token Validation

All tokens are validated for:

- **Signature**: Cryptographic signature verification
- **Expiration**: Token expiration time validation
- **Issuer**: Token issuer claim validation
- **Audience**: Token audience claim validation
- **Revocation**: Token revocation status check

## Redis Security

### Connection Security

- **Authentication**: Support for Redis authentication
- **SSL/TLS**: Support for encrypted connections
- **Network Security**: Configurable network access controls

### Data Security

- **Token Isolation**: Tokens stored with unique prefixes
- **Automatic Expiration**: Redis TTL for automatic token cleanup
- **Data Encryption**: Support for Redis encryption at rest

### Configuration Example

```ruby
JwtPhantomAuth.configure do |config|
  # Secure Redis connection
  config.redis_url = "redis://:password@redis.example.com:6379/0?ssl=true"
  
  # Or use custom Redis client with security settings
  config.redis_client = Redis.new(
    url: ENV['REDIS_URL'],
    ssl: true,
    ssl_params: { verify_mode: OpenSSL::SSL::VERIFY_PEER }
  )
end
```

## Best Practices

### 1. Secret Key Management

- **Strong Secret Key**: Use a strong, unique secret key
- **Environment Variables**: Store secret key in environment variables
- **Key Rotation**: Implement secret key rotation procedures
- **Key Length**: Use at least 256-bit keys

```ruby
# Use environment variable for secret key
config.secret_key = ENV['JWT_SECRET_KEY']
```

### 2. Token Expiry Configuration

- **Short Access Tokens**: Keep access tokens short-lived (15 minutes or less)
- **Long Refresh Tokens**: Use longer refresh tokens for user convenience
- **Phantom Token Expiry**: Keep phantom tokens very short-lived (5 minutes)

```ruby
config.access_token_expiry = 15 * 60      # 15 minutes
config.refresh_token_expiry = 7 * 24 * 60 * 60  # 7 days
config.phantom_token_expiry = 5 * 60      # 5 minutes
```

### 3. HTTPS Usage

- **Production Requirement**: Always use HTTPS in production
- **Token Transmission**: Protect tokens in transit
- **Secure Headers**: Use secure and httpOnly cookies when appropriate

### 4. Token Storage

- **Client Storage**: Store tokens securely on the client side
- **HttpOnly Cookies**: Use httpOnly cookies for refresh tokens
- **Local Storage**: Use localStorage/sessionStorage for access tokens
- **Token Rotation**: Implement automatic token refresh

### 5. Error Handling

- **Generic Errors**: Don't expose sensitive information in error messages
- **Logging**: Log security events without exposing sensitive data
- **Rate Limiting**: Implement rate limiting for authentication endpoints

```ruby
begin
  result = JwtPhantomAuth.token_manager.refresh_access_token(refresh_token)
rescue JwtPhantomAuth::TokenExpiredError
  render json: { error: 'Authentication required' }, status: :unauthorized
rescue JwtPhantomAuth::InvalidTokenError
  render json: { error: 'Authentication required' }, status: :unauthorized
end
```

## Security Considerations

### 1. Token Exposure

- **Client-Side Storage**: Tokens stored on client side are vulnerable to XSS
- **Network Transmission**: Tokens transmitted over HTTP are vulnerable to interception
- **Logging**: Ensure tokens are not logged in application logs

### 2. Token Replay Attacks

- **Token Revocation**: Implement proper token revocation
- **Token Rotation**: Use token rotation to prevent replay attacks
- **Blacklisting**: Maintain blacklist of revoked tokens

### 3. Token Hijacking

- **HTTPS**: Use HTTPS to prevent token interception
- **Secure Headers**: Implement security headers (HSTS, CSP, etc.)
- **Token Validation**: Validate tokens on every request

### 4. User Session Management

- **Logout**: Implement proper logout with token revocation
- **Session Timeout**: Implement session timeout mechanisms
- **Concurrent Sessions**: Consider limiting concurrent sessions

### 5. Redis Security

- **Network Access**: Restrict Redis network access
- **Authentication**: Use Redis authentication
- **Encryption**: Use Redis encryption at rest and in transit
- **Backup Security**: Secure Redis backups

## Threat Model

### Potential Threats

1. **Token Theft**: Unauthorized access to tokens
2. **Token Replay**: Reuse of captured tokens
3. **Token Forgery**: Creation of fake tokens
4. **Token Hijacking**: Interception of tokens in transit
5. **Token Brute Force**: Attempts to guess token values

### Mitigation Strategies

1. **Cryptographic Signing**: Prevents token forgery
2. **Token Expiration**: Limits token replay window
3. **Token Revocation**: Prevents use of compromised tokens
4. **HTTPS**: Prevents token interception
5. **Phantom Tokens**: Reduces token exposure
6. **Rate Limiting**: Prevents brute force attacks

### Security Monitoring

- **Failed Authentication**: Monitor failed authentication attempts
- **Token Revocation**: Monitor token revocation events
- **Suspicious Activity**: Monitor for suspicious token usage patterns
- **Redis Access**: Monitor Redis access and usage

### Incident Response

1. **Token Compromise**: Immediately revoke all tokens for affected users
2. **Secret Key Compromise**: Rotate secret key and reissue all tokens
3. **Redis Breach**: Revoke all tokens and investigate data exposure
4. **User Account Compromise**: Revoke all tokens for the user account

## Compliance

### GDPR Considerations

- **Data Minimization**: Only store necessary user data in tokens
- **Right to Erasure**: Implement token revocation for user deletion
- **Data Portability**: Ensure user data can be exported
- **Consent**: Obtain proper consent for data processing

### SOC 2 Considerations

- **Access Control**: Implement proper access controls
- **Audit Logging**: Log authentication and authorization events
- **Data Protection**: Protect sensitive data in transit and at rest
- **Incident Response**: Have incident response procedures

### PCI DSS Considerations

- **Token Security**: Ensure tokens don't contain sensitive payment data
- **Access Control**: Implement proper access controls
- **Audit Logging**: Log access to sensitive data
- **Data Encryption**: Encrypt sensitive data in transit and at rest 