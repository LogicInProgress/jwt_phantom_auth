# JWT Phantom Auth API Documentation

This document provides detailed API documentation for the JWT Phantom Auth gem.

## Table of Contents

- [Configuration](#configuration)
- [TokenManager](#tokenmanager)
- [PhantomTokenManager](#phantomtokenmanager)
- [UserAuthenticator](#userauthenticator)
- [Middleware](#middleware)
- [Errors](#errors)

## Configuration

The `JwtPhantomAuth::Configuration` class manages all configuration options for the gem.

### Instance Methods

#### `initialize`
Creates a new configuration instance with default values.

```ruby
config = JwtPhantomAuth::Configuration.new
```

#### `validate!`
Validates the configuration and raises errors if required fields are missing.

```ruby
config.validate!
# Raises ConfigurationError if validation fails
```

#### `redis_client`
Returns the Redis client instance, creating one if it doesn't exist.

```ruby
redis = config.redis_client
```

#### `phantom_tokens_enabled?`
Returns whether phantom tokens are enabled.

```ruby
enabled = config.phantom_tokens_enabled?
```

### Configuration Options

| Attribute | Type | Default | Description |
|-----------|------|---------|-------------|
| `secret_key` | String | `ENV['JWT_SECRET_KEY']` | Secret key for JWT signing |
| `algorithm` | String | `'HS256'` | JWT signing algorithm |
| `access_token_expiry` | Integer | `15 * 60` | Access token expiry in seconds |
| `refresh_token_expiry` | Integer | `7 * 24 * 60 * 60` | Refresh token expiry in seconds |
| `phantom_token_expiry` | Integer | `5 * 60` | Phantom token expiry in seconds |
| `redis_url` | String | `ENV['REDIS_URL']` | Redis connection URL |
| `redis_client` | Redis | `nil` | Custom Redis client instance |
| `user_model` | Class | `nil` | User model class |
| `user_identifier_field` | Symbol | `:email` | Field used to identify users |
| `password_field` | Symbol | `:password` | Password field name |
| `token_issuer` | String | `'jwt_phantom_auth'` | Token issuer claim |
| `token_audience` | String | `'api'` | Token audience claim |
| `enable_phantom_tokens` | Boolean | `true` | Enable phantom token functionality |
| `phantom_token_prefix` | String | `'phantom_'` | Prefix for phantom tokens in Redis |
| `access_token_prefix` | String | `'access_'` | Prefix for access tokens in Redis |

## TokenManager

The `JwtPhantomAuth::TokenManager` class handles JWT token generation, validation, and management.

### Instance Methods

#### `initialize(configuration)`
Creates a new TokenManager instance with the given configuration.

```ruby
token_manager = JwtPhantomAuth::TokenManager.new(configuration)
```

#### `generate_access_token(user)`
Generates a short-lived access token for a user.

**Parameters:**
- `user` (Object): The user object

**Returns:** String - The generated JWT access token

**Example:**
```ruby
access_token = token_manager.generate_access_token(user)
```

**Token Payload:**
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

#### `generate_refresh_token(user)`
Generates a long-lived refresh token for a user.

**Parameters:**
- `user` (Object): The user object

**Returns:** String - The generated JWT refresh token

**Example:**
```ruby
refresh_token = token_manager.generate_refresh_token(user)
```

**Token Payload:**
```json
{
  "user_id": 123,
  "token_type": "refresh",
  "jti": "unique_token_id",
  "iat": 1640995200,
  "exp": 1641600000,
  "iss": "jwt_phantom_auth",
  "aud": "api"
}
```

#### `refresh_access_token(refresh_token)`
Refreshes an access token using a valid refresh token.

**Parameters:**
- `refresh_token` (String): The refresh token

**Returns:** Hash - Contains new access and refresh tokens

**Example:**
```ruby
result = token_manager.refresh_access_token(refresh_token)
# Returns: { access_token: "new_access_token", refresh_token: "new_refresh_token" }
```

**Raises:**
- `TokenExpiredError`: If the refresh token has expired
- `InvalidTokenError`: If the refresh token is invalid

#### `decode_token(token)`
Decodes and validates a JWT token.

**Parameters:**
- `token` (String): The JWT token to decode

**Returns:** Hash - The decoded token payload

**Example:**
```ruby
payload = token_manager.decode_token(token)
# Returns: { user_id: 123, email: "user@example.com", ... }
```

**Raises:**
- `TokenExpiredError`: If the token has expired
- `InvalidTokenError`: If the token is invalid or malformed

#### `revoke_refresh_token(user_id, jti)`
Revokes a specific refresh token.

**Parameters:**
- `user_id` (Integer): The user ID
- `jti` (String): The JWT ID of the token to revoke

**Returns:** Boolean - True if successful

**Example:**
```ruby
success = token_manager.revoke_refresh_token(user_id, jti)
```

#### `revoke_all_refresh_tokens(user_id)`
Revokes all refresh tokens for a user.

**Parameters:**
- `user_id` (Integer): The user ID

**Returns:** Boolean - True if successful

**Example:**
```ruby
success = token_manager.revoke_all_refresh_tokens(user_id)
```

#### `token_revoked?(user_id, jti)`
Checks if a token has been revoked.

**Parameters:**
- `user_id` (Integer): The user ID
- `jti` (String): The JWT ID to check

**Returns:** Boolean - True if the token is revoked

**Example:**
```ruby
revoked = token_manager.token_revoked?(user_id, jti)
```

## PhantomTokenManager

The `JwtPhantomAuth::PhantomTokenManager` class manages phantom tokens for enhanced security.

### Instance Methods

#### `initialize(configuration)`
Creates a new PhantomTokenManager instance with the given configuration.

```ruby
phantom_manager = JwtPhantomAuth::PhantomTokenManager.new(configuration)
```

#### `generate_phantom_token(user)`
Generates a phantom token for a user.

**Parameters:**
- `user` (Object): The user object

**Returns:** String - The generated phantom token

**Example:**
```ruby
phantom_token = phantom_manager.generate_phantom_token(user)
```

#### `exchange_phantom_token(phantom_token)`
Exchanges a phantom token for a JWT access token.

**Parameters:**
- `phantom_token` (String): The phantom token to exchange

**Returns:** Hash - Contains the JWT access token and user ID

**Example:**
```ruby
result = phantom_manager.exchange_phantom_token(phantom_token)
# Returns: { access_token: "jwt_access_token", user_id: 123 }
```

**Raises:**
- `PhantomTokenError`: If the phantom token is invalid or expired
- `TokenExpiredError`: If the phantom token has expired

#### `revoke_phantom_token(phantom_token)`
Revokes a specific phantom token.

**Parameters:**
- `phantom_token` (String): The phantom token to revoke

**Returns:** Boolean - True if successful

**Example:**
```ruby
success = phantom_manager.revoke_phantom_token(phantom_token)
```

#### `phantom_token_valid?(phantom_token)`
Checks if a phantom token is valid and not expired.

**Parameters:**
- `phantom_token` (String): The phantom token to validate

**Returns:** Boolean - True if the token is valid

**Example:**
```ruby
valid = phantom_manager.phantom_token_valid?(phantom_token)
```

#### `get_user_id_from_phantom_token(phantom_token)`
Extracts the user ID from a phantom token.

**Parameters:**
- `phantom_token` (String): The phantom token

**Returns:** Integer - The user ID

**Example:**
```ruby
user_id = phantom_manager.get_user_id_from_phantom_token(phantom_token)
```

## UserAuthenticator

The `JwtPhantomAuth::UserAuthenticator` class handles user authentication and validation.

### Instance Methods

#### `initialize(configuration)`
Creates a new UserAuthenticator instance with the given configuration.

```ruby
authenticator = JwtPhantomAuth::UserAuthenticator.new(configuration)
```

#### `authenticate_user(identifier, password)`
Authenticates a user with identifier and password.

**Parameters:**
- `identifier` (String): User identifier (email, username, etc.)
- `password` (String): User password

**Returns:** Object - The authenticated user object or nil

**Example:**
```ruby
user = authenticator.authenticate_user("user@example.com", "password123")
```

#### `find_user_by_token(token)`
Finds a user by JWT token.

**Parameters:**
- `token` (String): The JWT token

**Returns:** Object - The user object or nil

**Example:**
```ruby
user = authenticator.find_user_by_token(token)
```

#### `find_user_by_id(user_id)`
Finds a user by ID.

**Parameters:**
- `user_id` (Integer): The user ID

**Returns:** Object - The user object or nil

**Example:**
```ruby
user = authenticator.find_user_by_id(123)
```

#### `validate_user(user)`
Validates that a user object is valid and active.

**Parameters:**
- `user` (Object): The user object to validate

**Returns:** Boolean - True if the user is valid

**Example:**
```ruby
valid = authenticator.validate_user(user)
```

## Middleware

The `JwtPhantomAuth::Middleware` class provides Rails middleware for automatic authentication.

### Instance Methods

#### `initialize(app)`
Creates a new middleware instance.

```ruby
middleware = JwtPhantomAuth::Middleware.new(app)
```

#### `call(env)`
Processes the request and adds authentication information to the environment.

**Parameters:**
- `env` (Hash): The Rack environment

**Returns:** Array - The Rack response

**Example:**
```ruby
status, headers, body = middleware.call(env)
```

### Environment Variables

The middleware adds the following variables to the Rack environment:

- `jwt_phantom_auth.user`: The authenticated user object
- `jwt_phantom_auth.token`: The JWT token used for authentication
- `jwt_phantom_auth.authenticated`: Boolean indicating if the request is authenticated

### Usage in Rails

```ruby
# config/application.rb
module YourApp
  class Application < Rails::Application
    config.middleware.use JwtPhantomAuth::Middleware
  end
end
```

### Accessing the Authenticated User

```ruby
# In your controllers
def current_user
  request.env['jwt_phantom_auth.user']
end

def authenticated?
  request.env['jwt_phantom_auth.authenticated']
end
```

## Errors

The gem provides several custom exception classes for error handling.

### Error Classes

#### `JwtPhantomAuth::Error`
Base error class for all gem errors.

#### `JwtPhantomAuth::AuthenticationError`
Raised when authentication fails.

#### `JwtPhantomAuth::TokenExpiredError`
Raised when a token has expired.

#### `JwtPhantomAuth::InvalidTokenError`
Raised when a token is invalid or malformed.

#### `JwtPhantomAuth::UserNotFoundError`
Raised when a user is not found.

#### `JwtPhantomAuth::PhantomTokenError`
Raised when phantom token operations fail.

#### `JwtPhantomAuth::ConfigurationError`
Raised when configuration validation fails.

### Error Handling Example

```ruby
begin
  result = JwtPhantomAuth.token_manager.refresh_access_token(refresh_token)
  # Handle successful refresh
rescue JwtPhantomAuth::TokenExpiredError => e
  # Handle expired token
  render json: { error: 'Token expired' }, status: :unauthorized
rescue JwtPhantomAuth::InvalidTokenError => e
  # Handle invalid token
  render json: { error: 'Invalid token' }, status: :unauthorized
rescue JwtPhantomAuth::Error => e
  # Handle other gem errors
  render json: { error: e.message }, status: :internal_server_error
end
```

## Global Methods

The gem provides several global methods for easy access to its functionality.

### `JwtPhantomAuth.configure`
Configures the gem with a block.

```ruby
JwtPhantomAuth.configure do |config|
  config.secret_key = ENV['JWT_SECRET_KEY']
  config.user_model = User
end
```

### `JwtPhantomAuth.configuration`
Returns the current configuration instance.

```ruby
config = JwtPhantomAuth.configuration
```

### `JwtPhantomAuth.token_manager`
Returns the global TokenManager instance.

```ruby
token_manager = JwtPhantomAuth.token_manager
```

### `JwtPhantomAuth.phantom_token_manager`
Returns the global PhantomTokenManager instance.

```ruby
phantom_manager = JwtPhantomAuth.phantom_token_manager
```

### `JwtPhantomAuth.user_authenticator`
Returns the global UserAuthenticator instance.

```ruby
authenticator = JwtPhantomAuth.user_authenticator
``` 