# frozen_string_literal: true

require 'securerandom'

module JwtPhantomAuth
  class PhantomTokenManager
    def initialize(configuration)
      @config = configuration
    end

    # Generate a phantom token (short-lived, opaque token)
    def generate_phantom_token(user)
      phantom_token = SecureRandom.hex(32)
      access_token = JwtPhantomAuth.token_manager.generate_access_token(user)
      
      # Store the mapping in Redis with short expiry
      redis_key = "#{@config.phantom_token_prefix}#{phantom_token}"
      @config.redis_client.setex(redis_key, @config.phantom_token_expiry, access_token)
      
      phantom_token
    end

    # Exchange phantom token for access token
    def exchange_phantom_token(phantom_token)
      redis_key = "#{@config.phantom_token_prefix}#{phantom_token}"
      access_token = @config.redis_client.get(redis_key)
      
      raise PhantomTokenError, 'Invalid or expired phantom token' unless access_token
      
      # Delete the phantom token after exchange (one-time use)
      @config.redis_client.del(redis_key)
      
      # Validate the access token
      payload = JwtPhantomAuth.token_manager.decode_token(access_token)
      
      {
        access_token: access_token,
        user_id: payload['user_id'],
        email: payload['email'],
        expires_in: payload['exp'] - Time.current.to_i
      }
    end

    # Generate phantom token pair (phantom + refresh)
    def generate_phantom_token_pair(user)
      {
        phantom_token: generate_phantom_token(user),
        refresh_token: JwtPhantomAuth.token_manager.generate_refresh_token(user),
        token_type: 'Phantom',
        expires_in: @config.phantom_token_expiry
      }
    end

    # Refresh phantom token using refresh token
    def refresh_phantom_token(refresh_token)
      # First refresh the access token
      token_pair = JwtPhantomAuth.token_manager.refresh_access_token(refresh_token)
      
      # Generate new phantom token
      phantom_token = generate_phantom_token(JwtPhantomAuth.user_authenticator.find_user(token_pair[:access_token]))
      
      {
        phantom_token: phantom_token,
        refresh_token: token_pair[:refresh_token],
        token_type: 'Phantom',
        expires_in: @config.phantom_token_expiry
      }
    end

    # Revoke phantom token
    def revoke_phantom_token(phantom_token)
      redis_key = "#{@config.phantom_token_prefix}#{phantom_token}"
      @config.redis_client.del(redis_key)
    end

    # Check if phantom token exists (without consuming it)
    def phantom_token_exists?(phantom_token)
      redis_key = "#{@config.phantom_token_prefix}#{phantom_token}"
      @config.redis_client.exists(redis_key) == 1
    end

    # Get phantom token info without consuming it
    def get_phantom_token_info(phantom_token)
      redis_key = "#{@config.phantom_token_prefix}#{phantom_token}"
      access_token = @config.redis_client.get(redis_key)
      
      return nil unless access_token
      
      begin
        payload = JwtPhantomAuth.token_manager.decode_token(access_token)
        {
          user_id: payload['user_id'],
          email: payload['email'],
          expires_in: payload['exp'] - Time.current.to_i
        }
      rescue JwtPhantomAuth::TokenExpiredError
        # Clean up expired token
        @config.redis_client.del(redis_key)
        nil
      end
    end

    # Clean up expired phantom tokens
    def cleanup_expired_phantom_tokens
      pattern = "#{@config.phantom_token_prefix}*"
      keys = @config.redis_client.keys(pattern)
      
      keys.each do |key|
        access_token = @config.redis_client.get(key)
        next unless access_token
        
        begin
          JwtPhantomAuth.token_manager.decode_token(access_token)
        rescue JwtPhantomAuth::TokenExpiredError
          @config.redis_client.del(key)
        end
      end
    end
  end
end 