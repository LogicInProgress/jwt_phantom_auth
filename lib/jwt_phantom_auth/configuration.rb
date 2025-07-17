# frozen_string_literal: true

require 'redis'

module JwtPhantomAuth
  class Configuration
    attr_accessor :secret_key,
                  :algorithm,
                  :access_token_expiry,
                  :refresh_token_expiry,
                  :phantom_token_expiry,
                  :redis_url,
                  :redis_client,
                  :user_model, # Legacy support
                  :user_identifier_field, # Legacy support
                  :password_field, # Legacy support
                  :token_issuer,
                  :token_audience,
                  :enable_phantom_tokens,
                  :phantom_token_prefix,
                  :access_token_prefix,
                  :model_registry

    def initialize
      # JWT Configuration
      @secret_key = ENV['JWT_SECRET_KEY'] || 'your-secret-key-change-in-production'
      @algorithm = 'HS256'
      @token_issuer = 'jwt_phantom_auth'
      @token_audience = 'api'

      # Token Expiry Times (in seconds)
      @access_token_expiry = 15 * 60      # 15 minutes
      @refresh_token_expiry = 7 * 24 * 60 * 60  # 7 days
      @phantom_token_expiry = 5 * 60      # 5 minutes

      # Redis Configuration
      @redis_url = ENV['REDIS_URL'] || 'redis://localhost:6379/0'
      @redis_client = nil

      # User Model Configuration (Legacy support)
      @user_model = nil
      @user_identifier_field = :email
      @password_field = :password
      
      # Model Registry for multi-model support
      @model_registry = ModelRegistry.new

      # Phantom Token Configuration
      @enable_phantom_tokens = true
      @phantom_token_prefix = 'phantom_'
      @access_token_prefix = 'access_'
    end

    def redis_client
      @redis_client ||= Redis.new(url: redis_url)
    end

    def validate!
      raise ConfigurationError, 'Secret key is required' if secret_key.nil? || secret_key.empty?
      
      # Legacy validation
      if user_model.nil? && model_registry.all_models.empty?
        raise ConfigurationError, 'Either user_model or at least one model in registry is required'
      end
      
      # Validate model registry if models are registered
      model_registry.validate! unless model_registry.all_models.empty?
      
      raise ConfigurationError, 'Access token expiry must be positive' if access_token_expiry <= 0
      raise ConfigurationError, 'Refresh token expiry must be positive' if refresh_token_expiry <= 0
      raise ConfigurationError, 'Phantom token expiry must be positive' if phantom_token_expiry <= 0
    end

    def phantom_tokens_enabled?
      enable_phantom_tokens
    end

    # Legacy support methods
    def get_user_model
      return user_model if user_model
      return model_registry.default_model.model_class if model_registry.default_model
      nil
    end

    def get_identifier_field
      return user_identifier_field if user_identifier_field
      return model_registry.default_model.identifier_field if model_registry.default_model
      :email
    end

    def get_password_field
      return password_field if password_field
      return model_registry.default_model.password_field if model_registry.default_model
      :password
    end

    # Multi-model support methods
    def register_model(model_name, model_class, options = {})
      model_registry.register(model_name, model_class, options)
    end

    def set_default_model(model_name)
      model_registry.default_model = model_name
    end

    def get_model_config(model_name = nil)
      return model_registry.get_model(model_name) if model_name
      model_registry.default_model
    end
  end
end 