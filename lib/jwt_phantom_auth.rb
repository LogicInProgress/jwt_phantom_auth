# frozen_string_literal: true

require_relative "jwt_phantom_auth/version"
require_relative "jwt_phantom_auth/errors"
require_relative "jwt_phantom_auth/model_registry"
require_relative "jwt_phantom_auth/token_manager"
require_relative "jwt_phantom_auth/phantom_token_manager"
require_relative "jwt_phantom_auth/user_authenticator"
require_relative "jwt_phantom_auth/middleware"
require_relative "jwt_phantom_auth/configuration"

module JwtPhantomAuth
  class Error < StandardError; end
  class AuthenticationError < Error; end
  class TokenExpiredError < Error; end
  class InvalidTokenError < Error; end
  class UserNotFoundError < Error; end

  class << self
    def configure
      yield configuration
    end

    def configuration
      @configuration ||= Configuration.new
    end

    def token_manager
      @token_manager ||= TokenManager.new(configuration)
    end

    def phantom_token_manager
      @phantom_token_manager ||= PhantomTokenManager.new(configuration)
    end

    def user_authenticator
      @user_authenticator ||= UserAuthenticator.new(configuration)
    end
  end
end
