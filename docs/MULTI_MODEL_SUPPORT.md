# Multi-Model Support

The JWT Phantom Auth gem now supports multiple models for authentication, allowing you to authenticate different types of users (e.g., regular users, admins, customers, etc.) with different configurations.

## Table of Contents

- [Overview](#overview)
- [Basic Setup](#basic-setup)
- [Model Registration](#model-registration)
- [Configuration Options](#configuration-options)
- [Usage Examples](#usage-examples)
- [Migration from Single Model](#migration-from-single-model)
- [Advanced Features](#advanced-features)

## Overview

The multi-model support allows you to:

- Register multiple models with different configurations
- Use different authentication methods for each model
- Customize token payloads per model
- Maintain backward compatibility with single-model setup

## Basic Setup

### 1. Register Models

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
  
  config.register_model(:customer, Customer, {
    identifier_field: :email,
    password_field: :password_digest,
    authentication_method: :authenticate_customer
  })
  
  # Set default model
  config.set_default_model(:user)
  
  # Phantom Token Configuration
  config.enable_phantom_tokens = true
end
```

### 2. Model Definitions

```ruby
# app/models/user.rb
class User < ApplicationRecord
  has_secure_password
  
  validates :email, presence: true, uniqueness: true
  validates :password, presence: true, on: :create
  
  def to_token_payload
    {
      email: email,
      role: 'user',
      permissions: ['read', 'write']
    }
  end
end

# app/models/admin.rb
class Admin < ApplicationRecord
  has_secure_password
  
  validates :username, presence: true, uniqueness: true
  validates :password, presence: true, on: :create
  
  def to_admin_token_payload
    {
      username: username,
      role: 'admin',
      permissions: ['read', 'write', 'delete', 'admin'],
      admin_level: admin_level
    }
  end
end

# app/models/customer.rb
class Customer < ApplicationRecord
  has_secure_password
  
  validates :email, presence: true, uniqueness: true
  validates :password, presence: true, on: :create
  
  def authenticate_customer(password)
    # Custom authentication logic
    authenticate(password) && active?
  end
  
  def to_token_payload
    {
      email: email,
      role: 'customer',
      customer_id: customer_number,
      subscription_status: subscription_status
    }
  end
end
```

## Model Registration

### Registration Options

When registering a model, you can specify the following options:

| Option | Default | Description |
|--------|---------|-------------|
| `identifier_field` | `:email` | Field used to identify the user |
| `password_field` | `:password` | Field containing the password |
| `token_payload_method` | `:to_token_payload` | Method to generate token payload |
| `authentication_method` | `:authenticate` | Method to authenticate the user |
| `find_method` | `:find_by` | Method to find users |

### Registration Examples

```ruby
# Basic registration
config.register_model(:user, User)

# With custom fields
config.register_model(:admin, Admin, {
  identifier_field: :username,
  password_field: :encrypted_password
})

# With custom authentication
config.register_model(:customer, Customer, {
  authentication_method: :authenticate_customer,
  token_payload_method: :to_customer_payload
})

# With custom find method
config.register_model(:api_client, ApiClient, {
  find_method: :find_by_api_key,
  identifier_field: :api_key
})
```

## Configuration Options

### Model-Specific Configuration

Each model can have its own configuration:

```ruby
config.register_model(:user, User, {
  identifier_field: :email,
  password_field: :password,
  token_payload_method: :to_token_payload,
  authentication_method: :authenticate,
  find_method: :find_by
})
```

### Global Configuration

Global settings apply to all models:

```ruby
config.secret_key = ENV['JWT_SECRET_KEY']
config.access_token_expiry = 15 * 60
config.refresh_token_expiry = 7 * 24 * 60 * 60
config.phantom_token_expiry = 5 * 60
```

## Usage Examples

### 1. Authentication with Specific Model

```ruby
# app/controllers/api/auth/sessions_controller.rb
class Api::Auth::SessionsController < ApplicationController
  def login
    # Authenticate user
    user = authenticate_user(params[:email], params[:password], :user)
    
    if user
      tokens = generate_tokens(user)
      render json: { user: user, tokens: tokens }
    else
      render json: { error: 'Invalid credentials' }, status: :unauthorized
    end
  end
  
  def admin_login
    # Authenticate admin
    admin = authenticate_user(params[:username], params[:password], :admin)
    
    if admin
      tokens = generate_tokens(admin)
      render json: { admin: admin, tokens: tokens }
    else
      render json: { error: 'Invalid credentials' }, status: :unauthorized
    end
  end
  
  def customer_login
    # Authenticate customer
    customer = authenticate_user(params[:email], params[:password], :customer)
    
    if customer
      tokens = generate_tokens(customer)
      render json: { customer: customer, tokens: tokens }
    else
      render json: { error: 'Invalid credentials' }, status: :unauthorized
    end
  end

  private

  def authenticate_user(identifier, password, model_name)
    JwtPhantomAuth.user_authenticator.authenticate(identifier, password, model_name)
  end

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
end
```

### 2. Registration with Specific Model

```ruby
# app/controllers/api/auth/registrations_controller.rb
class Api::Auth::RegistrationsController < ApplicationController
  def create_user
    user = JwtPhantomAuth.user_authenticator.register(user_params, :user)
    
    if user
      tokens = generate_tokens(user)
      render json: { user: user, tokens: tokens }, status: :created
    else
      render json: { errors: user.errors.full_messages }, status: :unprocessable_entity
    end
  end
  
  def create_admin
    admin = JwtPhantomAuth.user_authenticator.register(admin_params, :admin)
    
    if admin
      tokens = generate_tokens(admin)
      render json: { admin: admin, tokens: tokens }, status: :created
    else
      render json: { errors: admin.errors.full_messages }, status: :unprocessable_entity
    end
  end

  private

  def user_params
    params.permit(:email, :password, :password_confirmation, :first_name, :last_name)
  end

  def admin_params
    params.permit(:username, :password, :password_confirmation, :admin_level)
  end
end
```

### 3. Finding Users by Model

```ruby
# Find user by ID
user = JwtPhantomAuth.user_authenticator.find_user(user_id, :user)
admin = JwtPhantomAuth.user_authenticator.find_user(admin_id, :admin)

# Find user by identifier
user = JwtPhantomAuth.user_authenticator.find_user_by_identifier(email, :user)
admin = JwtPhantomAuth.user_authenticator.find_user_by_identifier(username, :admin)
```

### 4. Token Generation with Model-Specific Payloads

```ruby
# Tokens will automatically include model-specific payloads
user_tokens = JwtPhantomAuth.token_manager.generate_token_pair(user)
admin_tokens = JwtPhantomAuth.token_manager.generate_token_pair(admin)

# Token payloads will include the custom data from to_token_payload methods
# user_tokens will include: { email: "...", role: "user", permissions: [...] }
# admin_tokens will include: { username: "...", role: "admin", permissions: [...], admin_level: ... }
```

## Migration from Single Model

### From Legacy Configuration

If you're currently using the legacy single-model configuration:

```ruby
# Old configuration
JwtPhantomAuth.configure do |config|
  config.user_model = User
  config.user_identifier_field = :email
  config.password_field = :password
end
```

### To Multi-Model Configuration

```ruby
# New configuration (backward compatible)
JwtPhantomAuth.configure do |config|
  # Legacy configuration still works
  config.user_model = User
  config.user_identifier_field = :email
  config.password_field = :password
  
  # Or use the new multi-model approach
  config.register_model(:user, User, {
    identifier_field: :email,
    password_field: :password
  })
  config.set_default_model(:user)
end
```

### Gradual Migration

You can migrate gradually:

1. **Phase 1**: Keep legacy configuration, add new models
2. **Phase 2**: Migrate to model registry for all models
3. **Phase 3**: Remove legacy configuration

```ruby
# Phase 1: Mixed approach
JwtPhantomAuth.configure do |config|
  # Legacy for existing User model
  config.user_model = User
  
  # New registry for additional models
  config.register_model(:admin, Admin)
  config.register_model(:customer, Customer)
end
```

## Advanced Features

### 1. Custom Authentication Methods

```ruby
class ApiClient < ApplicationRecord
  def authenticate_api_client(api_key)
    # Custom authentication logic
    self.api_key == api_key && active?
  end
end

# Registration
config.register_model(:api_client, ApiClient, {
  authentication_method: :authenticate_api_client,
  identifier_field: :api_key
})
```

### 2. Custom Token Payloads

```ruby
class User < ApplicationRecord
  def to_token_payload
    {
      email: email,
      role: role,
      permissions: calculate_permissions,
      organization_id: organization_id,
      custom_field: some_custom_field
    }
  end
end
```

### 3. Model-Specific Token Expiry

```ruby
# You can implement model-specific token expiry in your models
class Admin < ApplicationRecord
  def token_expiry
    admin_level == 'super' ? 30.minutes : 15.minutes
  end
end
```

### 4. Dynamic Model Selection

```ruby
# In your controllers, you can dynamically select models
def authenticate_dynamic(identifier, password, user_type)
  case user_type
  when 'user'
    JwtPhantomAuth.user_authenticator.authenticate(identifier, password, :user)
  when 'admin'
    JwtPhantomAuth.user_authenticator.authenticate(identifier, password, :admin)
  when 'customer'
    JwtPhantomAuth.user_authenticator.authenticate(identifier, password, :customer)
  else
    nil
  end
end
```

### 5. Middleware with Model Detection

```ruby
# Custom middleware that detects the model type from the token
class ModelAwareMiddleware
  def call(env)
    token = extract_token(env)
    
    if token
      payload = JwtPhantomAuth.token_manager.decode_token(token)
      
      # Detect model type from token payload
      model_type = detect_model_type(payload)
      
      # Find user in the appropriate model
      user = JwtPhantomAuth.user_authenticator.find_user(payload['user_id'], model_type)
      
      env['jwt_phantom_auth.user'] = user
      env['jwt_phantom_auth.model_type'] = model_type
    end
    
    @app.call(env)
  end
  
  private
  
  def detect_model_type(payload)
    # Logic to determine model type from token payload
    case payload['role']
    when 'admin'
      :admin
    when 'customer'
      :customer
    else
      :user
    end
  end
end
```

## Best Practices

### 1. Model Organization

- Use descriptive model names (`:user`, `:admin`, `:customer`)
- Keep model configurations consistent
- Use meaningful identifier fields

### 2. Token Payload Design

- Include model type information in tokens
- Keep payloads minimal but informative
- Use consistent field names across models

### 3. Security Considerations

- Use different password fields for different models if needed
- Implement model-specific authentication logic
- Consider different token expiry times for different user types

### 4. Performance

- Use appropriate database indexes for identifier fields
- Consider caching for frequently accessed user data
- Optimize token payload generation

## Troubleshooting

### Common Issues

1. **Model not found**: Ensure the model is registered before use
2. **Authentication fails**: Check that the authentication method exists
3. **Token payload issues**: Verify the token payload method returns a hash
4. **Configuration errors**: Run `config.validate!` to check configuration

### Debugging

```ruby
# Check registered models
JwtPhantomAuth.configuration.model_registry.all_models

# Check default model
JwtPhantomAuth.configuration.model_registry.default_model

# Validate configuration
JwtPhantomAuth.configuration.validate!
```

This multi-model support provides flexibility while maintaining backward compatibility with existing single-model configurations. 