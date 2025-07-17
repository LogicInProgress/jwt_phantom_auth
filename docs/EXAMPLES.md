# Examples and Use Cases

This document provides practical examples and use cases for the JWT Phantom Auth gem.

## Table of Contents

- [Basic Setup](#basic-setup)
- [Authentication Flow](#authentication-flow)
- [API Integration](#api-integration)
- [Rails Integration](#rails-integration)
- [Advanced Configuration](#advanced-configuration)
- [Error Handling](#error-handling)
- [Testing](#testing)

## Basic Setup

### 1. Gem Installation

Add the gem to your Gemfile:

```ruby
# Gemfile
gem 'jwt_phantom_auth'
```

Install the gem:

```bash
bundle install
```

### 2. Configuration

Create an initializer:

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

### 3. User Model

Ensure your User model has the necessary fields:

```ruby
# app/models/user.rb
class User < ApplicationRecord
  has_secure_password
  
  validates :email, presence: true, uniqueness: true
  validates :password, presence: true, on: :create
  
  # Optional: Add role-based authorization
  enum role: { user: 0, admin: 1, moderator: 2 }
  
  def to_token_payload
    {
      user_id: id,
      email: email,
      role: role
    }
  end
end
```

## Authentication Flow

### 1. User Registration

```ruby
# app/controllers/api/auth/registrations_controller.rb
class Api::Auth::RegistrationsController < ApplicationController
  skip_before_action :verify_authenticity_token

  def create
    user = User.new(user_params)
    
    if user.save
      tokens = generate_tokens(user)
      render json: {
        user: user,
        tokens: tokens,
        message: 'User registered successfully'
      }, status: :created
    else
      render json: { 
        errors: user.errors.full_messages
      }, status: :unprocessable_entity
    end
  end

  private

  def user_params
    params.permit(:first_name, :last_name, :email, :password, :password_confirmation, :role)
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

### 2. User Login

```ruby
# app/controllers/api/auth/sessions_controller.rb
class Api::Auth::SessionsController < ApplicationController
  skip_before_action :verify_authenticity_token

  def create
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

  def destroy
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

### 3. Token Refresh

```ruby
# app/controllers/api/auth/tokens_controller.rb
class Api::Auth::TokensController < ApplicationController
  skip_before_action :verify_authenticity_token

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
end
```

## API Integration

### 1. Protected API Endpoints

```ruby
# app/controllers/api/posts_controller.rb
class Api::PostsController < ApplicationController
  before_action :authenticate_user!
  before_action :set_post, only: [:show, :update, :destroy]

  def index
    posts = Post.where(user: current_user)
    render json: posts
  end

  def show
    render json: @post
  end

  def create
    post = current_user.posts.build(post_params)
    
    if post.save
      render json: post, status: :created
    else
      render json: { errors: post.errors.full_messages }, status: :unprocessable_entity
    end
  end

  def update
    if @post.update(post_params)
      render json: @post
    else
      render json: { errors: @post.errors.full_messages }, status: :unprocessable_entity
    end
  end

  def destroy
    @post.destroy
    render json: { message: 'Post deleted successfully' }
  end

  private

  def set_post
    @post = current_user.posts.find(params[:id])
  end

  def post_params
    params.permit(:title, :content)
  end

  def current_user
    request.env['jwt_phantom_auth.user']
  end

  def authenticate_user!
    unless current_user
      render json: { error: 'Authentication required' }, status: :unauthorized
    end
  end
end
```

### 2. Role-Based Authorization

```ruby
# app/controllers/api/admin/users_controller.rb
class Api::Admin::UsersController < ApplicationController
  before_action :authenticate_user!
  before_action :require_admin!

  def index
    users = User.all
    render json: users
  end

  def show
    user = User.find(params[:id])
    render json: user
  end

  def update
    user = User.find(params[:id])
    
    if user.update(user_params)
      render json: user
    else
      render json: { errors: user.errors.full_messages }, status: :unprocessable_entity
    end
  end

  private

  def user_params
    params.permit(:email, :role, :first_name, :last_name)
  end

  def current_user
    request.env['jwt_phantom_auth.user']
  end

  def authenticate_user!
    unless current_user
      render json: { error: 'Authentication required' }, status: :unauthorized
    end
  end

  def require_admin!
    unless current_user&.admin?
      render json: { error: 'Admin access required' }, status: :forbidden
    end
  end
end
```

### 3. Phantom Token Exchange

```ruby
# app/controllers/api/auth/phantom_controller.rb
class Api::Auth::PhantomController < ApplicationController
  skip_before_action :verify_authenticity_token

  def exchange
    phantom_token = params[:phantom_token] || request.headers['X-Phantom-Token']
    
    if phantom_token
      begin
        result = JwtPhantomAuth.phantom_token_manager.exchange_phantom_token(phantom_token)
        user = User.find(result[:user_id])
        
        render json: {
          user: user,
          access_token: result[:access_token],
          message: 'Phantom token exchanged successfully'
        }
      rescue JwtPhantomAuth::PhantomTokenError, JwtPhantomAuth::TokenExpiredError => e
        render json: { error: e.message }, status: :unauthorized
      end
    else
      render json: { error: 'Phantom token is required' }, status: :bad_request
    end
  end
end
```

## Rails Integration

### 1. Application Controller

```ruby
# app/controllers/application_controller.rb
class ApplicationController < ActionController::Base
  protect_from_forgery with: :exception
  
  # Skip CSRF for API requests
  skip_before_action :verify_authenticity_token, if: :api_request?
  
  private

  def api_request?
    request.format.json?
  end

  def current_user
    request.env['jwt_phantom_auth.user']
  end

  def authenticated?
    request.env['jwt_phantom_auth.authenticated']
  end

  def authenticate_user!
    unless current_user
      render json: { error: 'Authentication required' }, status: :unauthorized
    end
  end

  def require_admin!
    authenticate_user!
    unless current_user.admin?
      render json: { error: 'Admin access required' }, status: :forbidden
    end
  end
end
```

### 2. Middleware Configuration

```ruby
# config/application.rb
module YourApp
  class Application < Rails::Application
    # ... other configuration
    
    # Add JWT Phantom Auth middleware
    config.middleware.use JwtPhantomAuth::Middleware
    
    # Optional: Configure middleware to skip certain paths
    config.middleware.use JwtPhantomAuth::Middleware, skip_paths: [
      '/api/auth/login',
      '/api/auth/register',
      '/api/auth/refresh',
      '/api/auth/phantom/exchange'
    ]
  end
end
```

### 3. Routes Configuration

```ruby
# config/routes.rb
Rails.application.routes.draw do
  namespace :api do
    namespace :auth do
      post 'register', to: 'registrations#create'
      post 'login', to: 'sessions#create'
      delete 'logout', to: 'sessions#destroy'
      post 'refresh', to: 'tokens#refresh'
      post 'phantom/exchange', to: 'phantom#exchange'
    end
    
    resources :posts
    resources :users, only: [:index, :show, :update]
    
    namespace :admin do
      resources :users
    end
  end
end
```

## Advanced Configuration

### 1. Custom Token Payload

```ruby
# app/models/user.rb
class User < ApplicationRecord
  has_secure_password
  
  def to_token_payload
    {
      user_id: id,
      email: email,
      role: role,
      permissions: permissions,
      organization_id: organization_id
    }
  end

  private

  def permissions
    case role
    when 'admin'
      ['read', 'write', 'delete', 'admin']
    when 'moderator'
      ['read', 'write', 'moderate']
    else
      ['read', 'write']
    end
  end
end
```

### 2. Custom Redis Configuration

```ruby
# config/initializers/jwt_phantom_auth.rb
JwtPhantomAuth.configure do |config|
  # ... other configuration
  
  # Custom Redis client with connection pooling
  config.redis_client = Redis.new(
    url: ENV['REDIS_URL'],
    ssl: true,
    ssl_params: { verify_mode: OpenSSL::SSL::VERIFY_PEER },
    timeout: 5,
    reconnect_attempts: 3
  )
end
```

### 3. Environment-Specific Configuration

```ruby
# config/initializers/jwt_phantom_auth.rb
JwtPhantomAuth.configure do |config|
  config.secret_key = ENV['JWT_SECRET_KEY']
  config.user_model = User
  
  case Rails.env
  when 'development'
    config.access_token_expiry = 30 * 60      # 30 minutes
    config.phantom_token_expiry = 10 * 60     # 10 minutes
    config.redis_url = 'redis://localhost:6379/0'
  when 'test'
    config.access_token_expiry = 5 * 60       # 5 minutes
    config.phantom_token_expiry = 2 * 60      # 2 minutes
    config.redis_url = 'redis://localhost:6379/1'
  when 'production'
    config.access_token_expiry = 15 * 60      # 15 minutes
    config.phantom_token_expiry = 5 * 60      # 5 minutes
    config.redis_url = ENV['REDIS_URL']
  end
end
```

## Error Handling

### 1. Global Error Handling

```ruby
# app/controllers/application_controller.rb
class ApplicationController < ActionController::Base
  rescue_from JwtPhantomAuth::TokenExpiredError do |exception|
    render json: { error: 'Token expired' }, status: :unauthorized
  end

  rescue_from JwtPhantomAuth::InvalidTokenError do |exception|
    render json: { error: 'Invalid token' }, status: :unauthorized
  end

  rescue_from JwtPhantomAuth::AuthenticationError do |exception|
    render json: { error: 'Authentication failed' }, status: :unauthorized
  end

  rescue_from JwtPhantomAuth::UserNotFoundError do |exception|
    render json: { error: 'User not found' }, status: :not_found
  end

  rescue_from JwtPhantomAuth::PhantomTokenError do |exception|
    render json: { error: 'Invalid phantom token' }, status: :unauthorized
  end
end
```

### 2. Custom Error Responses

```ruby
# app/controllers/api/auth/sessions_controller.rb
class Api::Auth::SessionsController < ApplicationController
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
    rescue JwtPhantomAuth::TokenExpiredError => e
      render json: { 
        error: 'Refresh token expired',
        code: 'REFRESH_TOKEN_EXPIRED',
        message: 'Please log in again'
      }, status: :unauthorized
    rescue JwtPhantomAuth::InvalidTokenError => e
      render json: { 
        error: 'Invalid refresh token',
        code: 'INVALID_REFRESH_TOKEN',
        message: 'Please provide a valid refresh token'
      }, status: :unauthorized
    end
  end
end
```

## Testing

### 1. RSpec Configuration

```ruby
# spec/rails_helper.rb
RSpec.configure do |config|
  config.include FactoryBot::Syntax::Methods
  
  # Helper method to generate test tokens
  config.include TokenHelpers
end

# spec/support/token_helpers.rb
module TokenHelpers
  def generate_test_tokens(user)
    access_token = JwtPhantomAuth.token_manager.generate_access_token(user)
    refresh_token = JwtPhantomAuth.token_manager.generate_refresh_token(user)
    
    {
      access_token: access_token,
      refresh_token: refresh_token
    }
  end

  def auth_headers(user)
    tokens = generate_test_tokens(user)
    { 'Authorization' => "Bearer #{tokens[:access_token]}" }
  end
end
```

### 2. Controller Tests

```ruby
# spec/controllers/api/posts_controller_spec.rb
require 'rails_helper'

RSpec.describe Api::PostsController, type: :controller do
  let(:user) { create(:user) }
  let(:headers) { auth_headers(user) }

  before do
    request.headers.merge!(headers)
  end

  describe 'GET #index' do
    it 'returns user posts' do
      post = create(:post, user: user)
      
      get :index
      
      expect(response).to have_http_status(:ok)
      expect(JSON.parse(response.body)).to include(
        hash_including('id' => post.id)
      )
    end

    it 'requires authentication' do
      request.headers.delete('Authorization')
      
      get :index
      
      expect(response).to have_http_status(:unauthorized)
    end
  end

  describe 'POST #create' do
    it 'creates a new post' do
      post_params = { title: 'Test Post', content: 'Test content' }
      
      expect {
        post :create, params: post_params
      }.to change(Post, :count).by(1)
      
      expect(response).to have_http_status(:created)
    end
  end
end
```

### 3. Integration Tests

```ruby
# spec/requests/api/auth_spec.rb
require 'rails_helper'

RSpec.describe 'API Authentication', type: :request do
  let(:user) { create(:user, email: 'test@example.com', password: 'password123') }

  describe 'POST /api/auth/login' do
    it 'authenticates user and returns tokens' do
      post '/api/auth/login', params: {
        email: 'test@example.com',
        password: 'password123'
      }

      expect(response).to have_http_status(:ok)
      
      json = JSON.parse(response.body)
      expect(json['user']['email']).to eq('test@example.com')
      expect(json['tokens']['access_token']).to be_present
      expect(json['tokens']['refresh_token']).to be_present
    end

    it 'returns error for invalid credentials' do
      post '/api/auth/login', params: {
        email: 'test@example.com',
        password: 'wrongpassword'
      }

      expect(response).to have_http_status(:unauthorized)
    end
  end

  describe 'POST /api/auth/refresh' do
    let(:tokens) { generate_test_tokens(user) }

    it 'refreshes access token' do
      post '/api/auth/refresh', params: {
        refresh_token: tokens[:refresh_token]
      }

      expect(response).to have_http_status(:ok)
      
      json = JSON.parse(response.body)
      expect(json['tokens']['access_token']).to be_present
      expect(json['tokens']['refresh_token']).to be_present
    end
  end
end
```

### 4. Factory Definitions

```ruby
# spec/factories/users.rb
FactoryBot.define do
  factory :user do
    sequence(:email) { |n| "user#{n}@example.com" }
    password { 'password123' }
    password_confirmation { 'password123' }
    first_name { 'John' }
    last_name { 'Doe' }
    role { 'user' }
  end

  factory :admin, parent: :user do
    role { 'admin' }
  end

  factory :moderator, parent: :user do
    role { 'moderator' }
  end
end

# spec/factories/posts.rb
FactoryBot.define do
  factory :post do
    title { 'Test Post' }
    content { 'This is a test post content.' }
    association :user
  end
end
``` 