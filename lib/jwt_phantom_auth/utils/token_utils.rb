# frozen_string_literal: true

module JwtPhantomAuth
  # Token-related utility methods
  module TokenUtils
    # Check if a token is a phantom token (64-character hex string)
    def phantom_token?(token)
      return false unless token.is_a?(String)
      token.length == 64 && token.match?(/\A[0-9a-f]+\z/i)
    end

    # Check if a token is a JWT token (contains dots)
    def jwt_token?(token)
      return false unless token.is_a?(String)
      token.count('.') == 2
    end

    # Extract token type from token string
    def token_type(token)
      return 'phantom' if phantom_token?(token)
      return 'jwt' if jwt_token?(token)
      'unknown'
    end

    # Generate a phantom token
    def generate_phantom_token
      SecureRandom.hex(32)
    end

    # Generate a JWT token ID
    def generate_jwt_id
      SecureRandom.uuid
    end

    # Extract payload from JWT token without verification
    def extract_jwt_payload(token)
      return nil unless jwt_token?(token)

      parts = token.split('.')
      return nil unless parts.length == 3

      begin
        payload_part = parts[1]
        # Add padding if needed
        payload_part += '=' * (4 - payload_part.length % 4) if payload_part.length % 4 != 0
        JSON.parse(Base64.urlsafe_decode64(payload_part))
      rescue StandardError
        nil
      end
    end

    # Check if JWT token is expired
    def jwt_expired?(token, clock_skew = 0)
      payload = extract_jwt_payload(token)
      return true unless payload

      exp = payload['exp']
      return true unless exp

      Time.current.to_i > (exp + clock_skew)
    end

    # Get JWT token expiration time
    def jwt_expiration_time(token)
      payload = extract_jwt_payload(token)
      return nil unless payload

      exp = payload['exp']
      return nil unless exp

      Time.at(exp)
    end

    # Get JWT token issued time
    def jwt_issued_time(token)
      payload = extract_jwt_payload(token)
      return nil unless payload

      iat = payload['iat']
      return nil unless iat

      Time.at(iat)
    end

    # Get payload identifier from JWT token
    def jwt_payload_identifier(token)
      payload = extract_jwt_payload(token)
      payload&.dig('payload_identifier')
    end

    # Get model type from JWT token
    def jwt_model_type(token)
      payload = extract_jwt_payload(token)
      payload&.dig('model_type')
    end

    # Validate JWT token structure
    def validate_jwt_structure(token)
      return false unless jwt_token?(token)

      parts = token.split('.')
      return false unless parts.length == 3

      # Check if all parts are base64 encoded
      parts.all? { |part| valid_base64_url?(part) }
    end

    # Check if string is valid base64 URL
    def valid_base64_url?(string)
      return false unless string.is_a?(String)
      return false if string.empty?

      # Base64 URL safe characters
      string.match?(/^[A-Za-z0-9\-_]+$/)
    end

    # Mask sensitive token parts for logging
    def mask_token(token, visible_chars = 8)
      return '***' unless token.is_a?(String) && token.length > visible_chars

      "#{token[0, visible_chars]}...#{token[-visible_chars, visible_chars]}"
    end

    # Validate token format
    def validate_token_format(token)
      return false unless token.is_a?(String)
      return false if token.empty?

      phantom_token?(token) || jwt_token?(token)
    end

    # Sanitize token for storage
    def sanitize_token(token)
      return nil unless token.is_a?(String)
      return nil if token.strip.empty?

      token.strip
    end

    # Compare tokens securely
    def secure_token_compare(token1, token2)
      return false unless token1.is_a?(String) && token2.is_a?(String)
      return false if token1.length != token2.length

      # Use constant-time comparison to prevent timing attacks
      result = 0
      token1.bytes.each_with_index do |byte, i|
        result |= byte ^ token2.bytes[i]
      end
      result.zero?
    end
  end
end
