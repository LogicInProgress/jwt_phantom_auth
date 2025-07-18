# frozen_string_literal: true

require 'securerandom'

module JwtPhantomAuth
  class PhantomTokenManager
    def initialize(configuration)
      @config = configuration
    end

    # Generate a phantom token (short-lived, opaque token)
    def generate_phantom_token(user)
      phantom_token = JwtPhantomAuth.utils.generate_phantom_token
      access_token = JwtPhantomAuth.token_manager.generate_access_token(user)

      # Store the mapping in Redis with short expiry
      redis_key = JwtPhantomAuth.utils.phantom_token_key(phantom_token, @config.phantom_token_prefix)
      JwtPhantomAuth.utils.redis_setex(@config.redis_client, redis_key, @config.phantom_token_expiry, access_token)

      phantom_token
    end

    # Exchange phantom token for access token
    def exchange_phantom_token(phantom_token)
      redis_key = JwtPhantomAuth.utils.phantom_token_key(phantom_token, @config.phantom_token_prefix)
      access_token = JwtPhantomAuth.utils.redis_get(@config.redis_client, redis_key)

      raise PhantomTokenError, "Invalid or expired phantom token" unless access_token

      # Delete the phantom token after exchange (one-time use)
      JwtPhantomAuth.utils.redis_delete(@config.redis_client, redis_key)

      # Validate the access token
      payload = JwtPhantomAuth.token_manager.decode_token(access_token)

      # Extract payload identifier and model type from the token payload
      payload_identifier = extract_payload_identifier_from_payload(payload)
      model_type = extract_model_type_from_payload(payload)

      {
        access_token: access_token,
        payload_identifier: payload_identifier,
        model_type: model_type,
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
      # Validate and decode the refresh token
      payload = JwtPhantomAuth.token_manager.decode_token(refresh_token)

      # Extract payload identifier and model type from the refresh token
      payload_identifier = extract_payload_identifier_from_payload(payload)
      model_type = extract_model_type_from_payload(payload)

      # Find the user
      user = find_user_by_payload_identifier_and_type(payload_identifier, model_type)
      raise UserNotFoundError, "User not found" unless user

      # Generate new phantom token pair
      generate_phantom_token_pair(user)
    end

    # Validate phantom token without exchanging
    def validate_phantom_token(phantom_token)
      redis_key = JwtPhantomAuth.utils.phantom_token_key(phantom_token, @config.phantom_token_prefix)
      JwtPhantomAuth.utils.redis_key_exists?(@config.redis_client, redis_key)
    end

    # Get phantom token info without exchanging
    def get_phantom_token_info(phantom_token)
      redis_key = JwtPhantomAuth.utils.phantom_token_key(phantom_token, @config.phantom_token_prefix)
      access_token = JwtPhantomAuth.utils.redis_get(@config.redis_client, redis_key)

      return nil unless access_token

      # Decode the access token to get info
      payload = JwtPhantomAuth.token_manager.decode_token(access_token)

      # Extract payload identifier and model type
      payload_identifier = extract_payload_identifier_from_payload(payload)
      model_type = extract_model_type_from_payload(payload)

      {
        payload_identifier: payload_identifier,
        model_type: model_type,
        expires_in: payload['exp'] - Time.current.to_i
      }
    end

    # Revoke phantom token
    def revoke_phantom_token(phantom_token)
      redis_key = JwtPhantomAuth.utils.phantom_token_key(phantom_token, @config.phantom_token_prefix)
      JwtPhantomAuth.utils.redis_delete(@config.redis_client, redis_key)
    end

    # Clean up expired phantom tokens
    def cleanup_expired_phantom_tokens
      pattern = JwtPhantomAuth.utils.phantom_token_pattern(@config.phantom_token_prefix)
      JwtPhantomAuth.utils.cleanup_expired_keys(@config.redis_client, pattern)
    end

    private

    def extract_payload_identifier_from_payload(payload)
      # Try different possible keys for payload identifier
      payload['payload_identifier'] || payload['user_id'] || payload['email']
    end

    def extract_model_type_from_payload(payload)
      payload['model_type']
    end

    def find_user_by_payload_identifier_and_type(payload_identifier, model_type)
      model_config = @config.model_registry.find_model_by_type(model_type)
      return nil unless model_config

      model_config.find_by_payload_identifier(payload_identifier)
    end
  end
end
