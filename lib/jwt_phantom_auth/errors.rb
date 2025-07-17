# frozen_string_literal: true

module JwtPhantomAuth
  # Base error class for all authentication errors
  class Error < StandardError; end

  # Raised when authentication fails
  class AuthenticationError < Error; end

  # Raised when a token has expired
  class TokenExpiredError < Error; end

  # Raised when a token is invalid or malformed
  class InvalidTokenError < Error; end

  # Raised when a user is not found
  class UserNotFoundError < Error; end

  # Raised when refresh token is invalid or expired
  class RefreshTokenError < Error; end

  # Raised when phantom token is invalid
  class PhantomTokenError < Error; end

  # Raised when configuration is invalid
  class ConfigurationError < Error; end

  # Raised when Redis connection fails
  class RedisConnectionError < Error; end
end 