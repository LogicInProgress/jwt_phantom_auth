# frozen_string_literal: true

require 'redis'

module JwtPhantomAuth
  class Configuration
    attr_accessor :secret_key,
                  :algorithm,
                  :refresh_token_expiry,
                  :phantom_token_expiry,
                  :redis_url,
                  :redis_client,
                  :token_issuer,
                  :token_audience,
                  :phantom_token_prefix,
                  :model_registry

    def initialize
      # JWT Configuration
      @secret_key = ENV['JWT_SECRET_KEY']
      @algorithm = 'HS256'
      @token_issuer = 'jwt_phantom_auth'
      @token_audience = 'api'

      # Token Expiry Times (in seconds)
      @refresh_token_expiry = 7 * 24 * 60 * 60  # 7 days
      @phantom_token_expiry = 5 * 60  # 5 minutes

      # Redis Configuration
      @redis_url = ENV['REDIS_URL'] || 'redis://localhost:6379/0'
      @redis_client = nil

      # Model Registry for multi-model support
      @model_registry = ModelRegistry.new

      # Phantom Token Configuration
      @phantom_token_prefix = 'phantom_'
    end

    # Sample redis client
    def redis_client
      @redis_client ||= Redis.new(url: redis_url)
    end

    # Validate configuration
    def validate!
      raise ConfigurationError, 'Secret key is required' if secret_key.nil? || secret_key.empty?

      # Validate model registry if models are registered
      model_registry.validate! unless model_registry.all_models.empty?

      raise ConfigurationError, 'Refresh token expiry must be positive' if refresh_token_expiry <= 0
      raise ConfigurationError, 'Phantom token expiry must be positive' if phantom_token_expiry <= 0
    end

    # Get access token expiry (same as phantom token expiry)
    def access_token_expiry
      phantom_token_expiry
    end

    # Set access token expiry (sets phantom token expiry)
    def access_token_expiry=(value)
      @phantom_token_expiry = value
    end

    # Register a model with its configuration
    def register_model(model_name, model_class, options = {})
      model_registry.register(model_name, model_class, options)
    end

    # Get model configuration for an object
    def config_for_object(object)
      model_registry.config_for_object(object)
    end
  end
end
