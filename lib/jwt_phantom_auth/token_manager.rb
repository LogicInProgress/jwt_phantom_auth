# frozen_string_literal: true

require 'jwt'
require 'securerandom'

module JwtPhantomAuth
  class TokenManager
    def initialize(configuration)
      @config = configuration
    end

    # Generate access token
    def generate_access_token(user)
      model_config = @config.config_for_object(user)
      
      # Get user info for token payload
      user_info = get_user_info(user, model_config)
      
      payload = {
        user_id: user.id,
        token_type: 'access',
        jti: SecureRandom.uuid,
        iat: Time.current.to_i,
        exp: Time.current.to_i + @config.access_token_expiry,
        iss: @config.token_issuer,
        aud: @config.token_audience
      }.merge(user_info)

      JWT.encode(payload, @config.secret_key, @config.algorithm)
    end

    # Generate refresh token
    def generate_refresh_token(user)
      payload = {
        user_id: user.id,
        token_type: 'refresh',
        jti: SecureRandom.uuid,
        iat: Time.current.to_i,
        exp: Time.current.to_i + @config.refresh_token_expiry,
        iss: @config.token_issuer,
        aud: @config.token_audience
      }

      refresh_token = JWT.encode(payload, @config.secret_key, @config.algorithm)
      
      # Store refresh token in Redis for revocation capability
      store_refresh_token(user.id, payload[:jti], refresh_token)
      
      refresh_token
    end

    # Validate and decode token
    def decode_token(token)
      decoded = JWT.decode(token, @config.secret_key, true, {
        algorithm: @config.algorithm,
        iss: @config.token_issuer,
        aud: @config.token_audience,
        verify_iss: true,
        verify_aud: true
      })
      
      payload = decoded.first
      
      # Check if token is revoked (for refresh tokens)
      if payload['token_type'] == 'refresh'
        raise RefreshTokenError, 'Refresh token has been revoked' unless refresh_token_valid?(payload['user_id'], payload['jti'])
      end
      
      payload
    rescue JWT::ExpiredSignature
      raise TokenExpiredError, 'Token has expired'
    rescue JWT::DecodeError => e
      raise InvalidTokenError, "Invalid token: #{e.message}"
    end

    # Revoke refresh token
    def revoke_refresh_token(user_id, jti)
      redis_key = "refresh_token:#{user_id}:#{jti}"
      @config.redis_client.del(redis_key)
    end

    # Revoke all refresh tokens for a user
    def revoke_all_refresh_tokens(user_id)
      pattern = "refresh_token:#{user_id}:*"
      keys = @config.redis_client.keys(pattern)
      @config.redis_client.del(*keys) unless keys.empty?
    end

    # Generate token pair (access + refresh)
    def generate_token_pair(user)
      {
        access_token: generate_access_token(user),
        refresh_token: generate_refresh_token(user),
        token_type: 'Bearer',
        expires_in: @config.access_token_expiry
      }
    end

    # Refresh access token using refresh token
    def refresh_access_token(refresh_token)
      payload = decode_token(refresh_token)
      
      raise InvalidTokenError, 'Invalid token type' unless payload['token_type'] == 'refresh'
      
      user = find_user(payload['user_id'])
      raise UserNotFoundError, 'User not found' unless user
      
      # Revoke the old refresh token
      revoke_refresh_token(payload['user_id'], payload['jti'])
      
      # Generate new token pair
      generate_token_pair(user)
    end

    private

    def get_user_info(user, model_config)
      # Try to use custom token payload method if available
      if user.respond_to?(model_config.token_payload_method)
        return user.send(model_config.token_payload_method)
      end
      
      # Fallback to default payload
      {
        email: user.send(model_config.identifier_field),
        created_at: user.created_at,
        updated_at: user.updated_at
      }
    end

    def store_refresh_token(user_id, jti, token)
      redis_key = "refresh_token:#{user_id}:#{jti}"
      @config.redis_client.setex(redis_key, @config.refresh_token_expiry, token)
    end

    def refresh_token_valid?(user_id, jti)
      redis_key = "refresh_token:#{user_id}:#{jti}"
      @config.redis_client.exists(redis_key) == 1
    end

    def find_user(user_id)
      # Try to find user using model registry first
      @config.model_registry.all_models.each do |_, config|
        user = config.model_class.find_by(id: user_id)
        return user if user
      end
      
      # Fallback to legacy user_model
      if @config.user_model
        @config.user_model.constantize.find_by(id: user_id)
      end
    end
  end
end 