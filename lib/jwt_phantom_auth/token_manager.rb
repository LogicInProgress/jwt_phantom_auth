# frozen_string_literal: true

require "jwt"
require "securerandom"

module JwtPhantomAuth
  class TokenManager
    def initialize(configuration)
      @config = configuration
    end

    # Generate an access token for a user
    def generate_access_token(user)
      model_config = @config.config_for_object(user)
      raise ConfigurationError, "No model configuration found for user" unless model_config

      payload = get_user_info(user, model_config)
      payload.merge!(
        token_type: "access",
        jti: JwtPhantomAuth.utils.generate_jwt_id,
        iat: Time.current.to_i,
        exp: Time.current.to_i + @config.access_token_expiry,
        iss: @config.token_issuer,
        aud: @config.token_audience
      )

      JWT.encode(payload, @config.secret_key, @config.algorithm)
    end

    # Generate a refresh token for a user
    def generate_refresh_token(user)
      model_config = @config.config_for_object(user)
      raise ConfigurationError, "No model configuration found for user" unless model_config

      payload_identifier = model_config.get_payload_identifier(user)
      model_type = model_config.model_name

      payload = {
        token_type: "refresh",
        payload_identifier: payload_identifier,
        model_type: model_type,
        jti: JwtPhantomAuth.utils.generate_jwt_id,
        iat: Time.current.to_i,
        exp: Time.current.to_i + @config.refresh_token_expiry,
        iss: @config.token_issuer,
        aud: @config.token_audience
      }

      token = JWT.encode(payload, @config.secret_key, @config.algorithm)

      # Store refresh token in Redis for revocation capability
      redis_key = JwtPhantomAuth.utils.refresh_token_key(model_type, payload_identifier, payload[:jti])
      JwtPhantomAuth.utils.redis_setex(@config.redis_client, redis_key, @config.refresh_token_expiry, token)

      token
    end

    # Decode and validate a JWT token
    def decode_token(token)
      decoded = JWT.decode(token, @config.secret_key, true, {
        algorithm: @config.algorithm,
        verify_iss: true,
        verify_aud: true,
        iss: @config.token_issuer,
        aud: @config.token_audience
      })

      payload = decoded[0]
      raise TokenExpiredError, "Token has expired" if JwtPhantomAuth.utils.jwt_expired?(token)

      payload
    rescue JWT::ExpiredSignature
      raise TokenExpiredError, "Token has expired"
    rescue JWT::DecodeError => e
      raise InvalidTokenError, "Invalid token: #{e.message}"
    end

    # Refresh an access token using a refresh token
    def refresh_access_token(refresh_token)
      # Decode the refresh token
      payload = decode_token(refresh_token)
      raise RefreshTokenError, "Invalid refresh token" unless payload["token_type"] == "refresh"

      # Extract payload identifier and model type
      payload_identifier = payload["payload_identifier"]
      model_type = payload["model_type"]

      # Verify refresh token is still valid in Redis
      redis_key = JwtPhantomAuth.utils.refresh_token_key(model_type, payload_identifier, payload["jti"])
      unless JwtPhantomAuth.utils.redis_key_exists?(@config.redis_client, redis_key)
        raise RefreshTokenError, "Refresh token has been revoked"
      end

      # Find the user
      user = find_user_by_payload_identifier_and_type(payload_identifier, model_type)
      raise UserNotFoundError, "User not found" unless user

      # Generate new token pair
      {
        access_token: generate_access_token(user),
        refresh_token: generate_refresh_token(user)
      }
    end

    # Revoke a refresh token
    def revoke_refresh_token(refresh_token)
      payload = decode_token(refresh_token)
      raise RefreshTokenError, "Invalid refresh token" unless payload["token_type"] == "refresh"

      redis_key = JwtPhantomAuth.utils.refresh_token_key(
        payload["model_type"],
        payload["payload_identifier"],
        payload["jti"]
      )
      JwtPhantomAuth.utils.redis_delete(@config.redis_client, redis_key)
    end

    # Revoke all refresh tokens for a user
    def revoke_all_refresh_tokens(user)
      model_config = @config.config_for_object(user)
      return unless model_config

      payload_identifier = model_config.get_payload_identifier(user)
      model_type = model_config.model_name

      pattern = JwtPhantomAuth.utils.refresh_token_pattern(model_type, payload_identifier)
      keys = JwtPhantomAuth.utils.redis_keys(@config.redis_client, pattern)
      JwtPhantomAuth.utils.redis_delete_multiple(@config.redis_client, keys) unless keys.empty?
    end

    private

    def get_user_info(user, model_config)
      # Get the payload identifier for this user
      payload_identifier = model_config.get_payload_identifier(user)
      model_type = model_config.model_name

      # Build the payload with essential information
      payload = {
        payload_identifier: payload_identifier,
        model_type: model_type
      }

      # Add custom payload if the model has a custom_payload method
      method_name = "#{model_config.token_payload_method}".to_sym
      if user.respond_to?(method_name)
        custom_data = user.send(method_name)
        payload.merge!(custom_data) if custom_data.is_a?(Hash)
      end

      payload
    end

    def find_user_by_payload_identifier_and_type(payload_identifier, model_type)
      model_config = @config.model_registry.find_model_by_type(model_type)
      return nil unless model_config

      model_config.find_by_payload_identifier(payload_identifier)
    end
  end
end
