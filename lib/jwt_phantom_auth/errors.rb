# frozen_string_literal: true

module JwtPhantomAuth
  # Base error class for JWT Phantom Auth
  class Error < StandardError; end

  # Configuration errors
  class ConfigurationError < Error; end

  # Token-related errors
  class TokenError < Error; end
  class TokenExpiredError < TokenError; end
  class InvalidTokenError < TokenError; end
  class RefreshTokenError < TokenError; end

  # Phantom token errors
  class PhantomTokenError < TokenError; end

  # User-related errors
  class UserError < Error; end
  class UserNotFoundError < UserError; end
  class AuthenticationError < UserError; end
  class RegistrationError < UserError; end
  class PasswordResetError < UserError; end

  # Redis errors
  class RedisError < Error; end
end
