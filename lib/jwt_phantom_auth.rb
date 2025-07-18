# frozen_string_literal: true

require_relative "jwt_phantom_auth/version"
require_relative "jwt_phantom_auth/errors"
require_relative "jwt_phantom_auth/model_registry"
require_relative "jwt_phantom_auth/token_manager"
require_relative "jwt_phantom_auth/phantom_token_manager"
require_relative "jwt_phantom_auth/user_authenticator"
require_relative "jwt_phantom_auth/middleware"
require_relative "jwt_phantom_auth/configuration"
require_relative "jwt_phantom_auth/utils"

module JwtPhantomAuth
  class << self
    # Configure the JWT Phantom Auth system
    #
    # This method accepts a block that allows you to configure all aspects
    # of the authentication system including JWT settings, Redis connection,
    # token expiry times, and user model configurations.
    #
    # @yield [Configuration] The configuration object to customize
    # @example
    #   JwtPhantomAuth.configure do |config|
    #     config.secret_key = ENV['JWT_SECRET_KEY']
    #     config.redis_url = ENV['REDIS_URL']
    #     config.phantom_token_expiry = 5 * 60  # 5 minutes
    #     config.refresh_token_expiry = 7 * 24 * 60 * 60  # 7 days
    #   end
    def configure
      yield configuration
    end

    # Get the global configuration instance
    #
    # Returns a singleton Configuration instance that holds all the settings
    # for the JWT Phantom Auth system. This includes JWT settings, Redis
    # configuration, token expiry times, and model registrations.
    #
    # @return [Configuration] The global configuration instance
    def configuration
      @configuration ||= Configuration.new
    end

    # Get the global token manager instance
    #
    # The TokenManager handles all JWT token operations including:
    # - Generating access and refresh tokens
    # - Validating and decoding tokens
    # - Refreshing access tokens using refresh tokens
    # - Revoking refresh tokens
    # - Managing token storage in Redis
    #
    # @return [TokenManager] The global token manager instance
    def token_manager
      @token_manager ||= TokenManager.new(configuration)
    end

    # Get the global phantom token manager instance
    #
    # The PhantomTokenManager handles phantom token operations including:
    # - Generating short-lived phantom tokens
    # - Exchanging phantom tokens for access tokens
    # - Managing phantom token storage in Redis
    # - Cleaning up expired phantom tokens
    # - One-time use token validation
    #
    # @return [PhantomTokenManager] The global phantom token manager instance
    def phantom_token_manager
      @phantom_token_manager ||= PhantomTokenManager.new(configuration)
    end

    # Get the global user authenticator instance
    #
    # The UserAuthenticator handles user authentication operations including:
    # - Authenticating users with email/username and password
    # - Registering new users
    # - Finding users by ID or identifier
    # - Password hashing and verification
    # - Password reset functionality
    # - Multi-model user support
    #
    # @return [UserAuthenticator] The global user authenticator instance
    def user_authenticator
      @user_authenticator ||= UserAuthenticator.new(configuration)
    end

    # Get the global utilities instance
    #
    # The Utils module provides a comprehensive set of utility methods for:
    # - Token validation and manipulation
    # - Redis operations and key management
    # - Data validation and sanitization
    # - Security operations (hashing, encryption, etc.)
    # - Time calculations and formatting
    # - General utility functions
    #
    # @return [Utils] The global utilities module
    def utils
      Utils
    end
  end
end
