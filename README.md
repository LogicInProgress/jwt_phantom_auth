# JWT Phantom Auth

A comprehensive JWT authentication gem that implements the phantom token technique, providing secure API authentication with short-lived access tokens and long-lived refresh tokens.

## Features

- **JWT-based Authentication**: Secure token-based authentication using JSON Web Tokens
- **Phantom Token Technique**: Enhanced security with short-lived phantom tokens for API access
- **Refresh Token Support**: Long-lived refresh tokens for seamless user experience
- **Multi-Model Support**: Support for multiple user models (users, admins, customers, etc.)
- **Redis Integration**: Token storage and management using Redis
- **Rails Middleware**: Easy integration with Rails applications
- **Configurable**: Flexible configuration options for various use cases
- **Error Handling**: Comprehensive error handling with custom exceptions

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'jwt_phantom_auth'
```

And then execute:

```bash
bundle install
```

Or install it yourself as:

```bash
gem install jwt_phantom_auth
```

## Quick Start

### 1. Configuration

Create an initializer in your Rails application:

#### Single Model Configuration (Legacy)

```ruby
# config/initializers/jwt_phantom_auth.rb
JwtPhantomAuth.configure do |config|
  # JWT Configuration
  config.secret_key = ENV['JWT_SECRET_KEY']
  config.algorithm = 'HS256'
  
  # Token Expiry Times
  config.access_token_expiry = 15 * 60      # 15 minutes
  config.refresh_token_expiry = 7 * 24 * 60 * 60  # 7 days
  config.phantom_token_expiry = 5 * 60      # 5 minutes
  
  # Redis Configuration
  config.redis_url = ENV['REDIS_URL']
  
  # User Model Configuration
  config.user_model = User
  config.user_identifier_field = :email
  config.password_field = :password
  
  # Phantom Token Configuration
  config.enable_phantom_tokens = true
end
```

#### Multi-Model Configuration (Recommended)

```ruby
# config/initializers/jwt_phantom_auth.rb
JwtPhantomAuth.configure do |config|
  # JWT Configuration
  config.secret_key = ENV['JWT_SECRET_KEY']
  config.algorithm = 'HS256'
  
  # Token Expiry Times
  config.access_token_expiry = 15 * 60      # 15 minutes
  config.refresh_token_expiry = 7 * 24 * 60 * 60  # 7 days
  config.phantom_token_expiry = 5 * 60      # 5 minutes
  
  # Redis Configuration
  config.redis_url = ENV['REDIS_URL']
  
  # Register multiple models
  config.register_model(:user, User, {
    identifier_field: :email,
    password_field: :password,
    token_payload_method: :to_token_payload
  })
  
  config.register_model(:admin, Admin, {
    identifier_field: :username,
    password_field: :encrypted_password,
    token_payload_method: :to_admin_token_payload
  })
  
  # Set default model
  config.set_default_model(:user)
  
  # Phantom Token Configuration
  config.enable_phantom_tokens = true
end
```

### 2. Add Middleware

Add the middleware to your Rails application:

```ruby
# config/application.rb
module YourApp
  class Application < Rails::Application
    # ... other configuration
    
    # Add JWT Phantom Auth middleware
    config.middleware.use JwtPhantomAuth::Middleware
  end
end
```

### 3. User Model Setup

Ensure your User model includes the necessary fields:

```ruby
# app/models/user.rb
class User < ApplicationRecord
  has_secure_password
  
  # Add any additional fields you need
  validates :email, presence: true, uniqueness: true
  validates :password, presence: true, on: :create
end
```

### 4. Authentication Controller

Create an authentication controller:

```ruby
# app/controllers/api/auth/sessions_controller.rb
class Api::Auth::SessionsController < ApplicationController
  skip_before_action :verify_authenticity_token

  def login
    user = User.find_by(email: params[:email])
    
    if user&.authenticate(params[:password])
      tokens = generate_tokens(user)
      render json: {
        user: user,
        tokens: tokens,
        message: 'Login successful'
      }
    else
      render json: { 
        error: 'Invalid email or password'
      }, status: :unauthorized
    end
  end

  def refresh
    refresh_token = params[:refresh_token]
    
    begin
      result = JwtPhantomAuth.token_manager.refresh_access_token(refresh_token)
      user = User.find(JwtPhantomAuth.token_manager.decode_token(result[:access_token])['user_id'])
      
      render json: {
        user: user,
        tokens: result,
        message: 'Tokens refreshed successfully'
      }
    rescue JwtPhantomAuth::TokenExpiredError, JwtPhantomAuth::InvalidTokenError => e
      render json: { error: e.message }, status: :unauthorized
    end
  end

  def logout
    token = extract_token_from_request
    
    if token
      payload = JwtPhantomAuth.token_manager.decode_token(token)
      JwtPhantomAuth.token_manager.revoke_all_refresh_tokens(payload['user_id'])
      
      render json: { message: 'Logged out successfully' }
    else
      render json: { error: 'No token provided' }, status: :bad_request
    end
  end

  private

  def generate_tokens(user)
    access_token = JwtPhantomAuth.token_manager.generate_access_token(user)
    refresh_token = JwtPhantomAuth.token_manager.generate_refresh_token(user)

    phantom_token = nil
    if JwtPhantomAuth.configuration.phantom_tokens_enabled?
      phantom_token = JwtPhantomAuth.phantom_token_manager.generate_phantom_token(user)
    end

    {
      access_token: access_token,
      refresh_token: refresh_token,
      phantom_token: phantom_token,
      token_type: 'Bearer',
      expires_in: JwtPhantomAuth.configuration.access_token_expiry
    }
  end

  def extract_token_from_request
    auth_header = request.headers['Authorization']
    if auth_header && auth_header.start_with?('Bearer ')
      auth_header.split(' ').last
    else
      params[:token]
    end
  end
end
```

## Multi-Model Support

The gem supports multiple user models, allowing you to authenticate different types of users (users, admins, customers, etc.) with different configurations.

### Basic Multi-Model Setup

```ruby
# Register multiple models
config.register_model(:user, User, {
  identifier_field: :email,
  password_field: :password,
  token_payload_method: :to_token_payload
})

config.register_model(:admin, Admin, {
  identifier_field: :username,
  password_field: :encrypted_password,
  token_payload_method: :to_admin_token_payload
})

config.register_model(:customer, Customer, {
  identifier_field: :email,
  password_field: :password_digest,
  authentication_method: :authenticate_customer
})
```

### Usage with Multiple Models

```ruby
# Authenticate different user types
user = JwtPhantomAuth.user_authenticator.authenticate(email, password, :user)
admin = JwtPhantomAuth.user_authenticator.authenticate(username, password, :admin)
customer = JwtPhantomAuth.user_authenticator.authenticate(email, password, :customer)

# Generate tokens for different models
user_tokens = JwtPhantomAuth.token_manager.generate_token_pair(user)
admin_tokens = JwtPhantomAuth.token_manager.generate_token_pair(admin)
```

For detailed multi-model documentation, see [Multi-Model Support](docs/MULTI_MODEL_SUPPORT.md).

## Configuration Options

### JWT Configuration

| Option | Default | Description |
|--------|---------|-------------|
| `secret_key` | `ENV['JWT_SECRET_KEY']` | Secret key for JWT signing |
| `algorithm` | `'HS256'` | JWT signing algorithm |
| `token_issuer` | `'jwt_phantom_auth'` | Token issuer claim |
| `token_audience` | `'api'` | Token audience claim |

### Token Expiry Configuration

| Option | Default | Description |
|--------|---------|-------------|
| `access_token_expiry` | `15 * 60` | Access token expiry in seconds |
| `refresh_token_expiry` | `7 * 24 * 60 * 60` | Refresh token expiry in seconds |
| `phantom_token_expiry` | `5 * 60` | Phantom token expiry in seconds |

### Redis Configuration

| Option | Default | Description |
|--------|---------|-------------|
| `redis_url` | `ENV['REDIS_URL']` | Redis connection URL |
| `redis_client` | `nil` | Custom Redis client instance |

### User Model Configuration

| Option | Default | Description |
|--------|---------|-------------|
| `user_model` | `nil` | User model class (required) |
| `user_identifier_field` | `:email` | Field used to identify users |
| `password_field` | `:password` | Password field name |

### Phantom Token Configuration

| Option | Default | Description |
|--------|---------|-------------|
| `enable_phantom_tokens` | `true` | Enable phantom token functionality |
| `phantom_token_prefix` | `'phantom_'` | Prefix for phantom tokens in Redis |
| `access_token_prefix` | `'access_'` | Prefix for access tokens in Redis |

## API Reference

### TokenManager

The main class for managing JWT tokens.

#### Methods

##### `generate_access_token(user)`
Generates a short-lived access token for a user.

```ruby
access_token = JwtPhantomAuth.token_manager.generate_access_token(user)
```

##### `generate_refresh_token(user)`
Generates a long-lived refresh token for a user.

```ruby
refresh_token = JwtPhantomAuth.token_manager.generate_refresh_token(user)
```

##### `refresh_access_token(refresh_token)`
Refreshes an access token using a valid refresh token.

```ruby
result = JwtPhantomAuth.token_manager.refresh_access_token(refresh_token)
# Returns: { access_token: "new_access_token", refresh_token: "new_refresh_token" }
```

##### `decode_token(token)`
Decodes and validates a JWT token.

```ruby
payload = JwtPhantomAuth.token_manager.decode_token(token)
```

##### `revoke_refresh_token(user_id, jti)`
Revokes a specific refresh token.

```ruby
JwtPhantomAuth.token_manager.revoke_refresh_token(user_id, jti)
```

##### `revoke_all_refresh_tokens(user_id)`
Revokes all refresh tokens for a user.

```ruby
JwtPhantomAuth.token_manager.revoke_all_refresh_tokens(user_id)
```

### PhantomTokenManager

Manages phantom tokens for enhanced security.

#### Methods

##### `generate_phantom_token(user)`
Generates a phantom token for a user.

```ruby
phantom_token = JwtPhantomAuth.phantom_token_manager.generate_phantom_token(user)
```

##### `exchange_phantom_token(phantom_token)`
Exchanges a phantom token for a JWT access token.

```ruby
result = JwtPhantomAuth.phantom_token_manager.exchange_phantom_token(phantom_token)
# Returns: { access_token: "jwt_access_token", user_id: user_id }
```

##### `revoke_phantom_token(phantom_token)`
Revokes a specific phantom token.

```ruby
JwtPhantomAuth.phantom_token_manager.revoke_phantom_token(phantom_token)
```

### UserAuthenticator

Handles user authentication and validation.

#### Methods

##### `authenticate_user(identifier, password)`
Authenticates a user with identifier and password.

```ruby
user = JwtPhantomAuth.user_authenticator.authenticate_user(email, password)
```

##### `find_user_by_token(token)`
Finds a user by JWT token.

```ruby
user = JwtPhantomAuth.user_authenticator.find_user_by_token(token)
```

## Error Handling

The gem provides several custom exceptions:

- `JwtPhantomAuth::AuthenticationError` - General authentication errors
- `JwtPhantomAuth::TokenExpiredError` - Token has expired
- `JwtPhantomAuth::InvalidTokenError` - Token is invalid or malformed
- `JwtPhantomAuth::UserNotFoundError` - User not found
- `JwtPhantomAuth::PhantomTokenError` - Phantom token related errors

## Phantom Token Technique

The phantom token technique enhances security by:

1. **Short-lived Phantom Tokens**: Phantom tokens have a very short lifespan (typically 5 minutes)
2. **Opaque Tokens**: Phantom tokens are opaque and don't contain sensitive information
3. **Exchange Mechanism**: Phantom tokens are exchanged for JWT access tokens when needed
4. **Reduced Exposure**: Sensitive JWT tokens are only exposed when actively used

### Flow

1. User authenticates and receives a phantom token
2. Client uses phantom token for API requests
3. Middleware exchanges phantom token for JWT access token
4. JWT token is used for authorization
5. Phantom token is revoked after exchange

## Middleware

The `JwtPhantomAuth::Middleware` automatically handles:

- Token extraction from Authorization header
- Phantom token exchange
- User authentication
- Request authentication status

The authenticated user is available in `request.env['jwt_phantom_auth.user']`.

## Security Considerations

1. **Secret Key**: Always use a strong, unique secret key in production
2. **HTTPS**: Use HTTPS in production to protect tokens in transit
3. **Token Storage**: Store tokens securely on the client side
4. **Token Expiry**: Use appropriate token expiry times for your use case
5. **Redis Security**: Secure your Redis instance and use authentication

## Development

After checking out the repo, run `bin/setup` to install dependencies. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and the created tag, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).
