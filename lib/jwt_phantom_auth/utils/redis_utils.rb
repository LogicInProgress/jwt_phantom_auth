# frozen_string_literal: true

module JwtPhantomAuth
  # Redis-related utility methods
  module RedisUtils
    # Generate Redis key for phantom token
    def phantom_token_key(phantom_token, prefix = "phantom_")
      "#{prefix}#{phantom_token}"
    end

    # Generate Redis key for refresh token
    def refresh_token_key(model_type, payload_identifier, jti, prefix = "refresh_token:")
      "#{prefix}#{model_type}:#{payload_identifier}:#{jti}"
    end

    # Generate Redis key for password reset token
    def password_reset_key(model_type, payload_identifier, prefix = "password_reset:")
      "#{prefix}#{model_type}:#{payload_identifier}"
    end

    # Generate Redis key pattern for refresh tokens
    def refresh_token_pattern(model_type, payload_identifier, prefix = "refresh_token:")
      "#{prefix}#{model_type}:#{payload_identifier}:*"
    end

    # Generate Redis key pattern for password reset tokens
    def password_reset_pattern(model_type, prefix = "password_reset:")
      "#{prefix}#{model_type}:*"
    end

    # Generate Redis key pattern for phantom tokens
    def phantom_token_pattern(prefix = "phantom_")
      "#{prefix}*"
    end

    # Check if Redis key exists
    def redis_key_exists?(redis_client, key)
      return false unless redis_client
      redis_client.exists(key) == 1
    rescue StandardError
      false
    end

    # Get Redis key value
    def redis_get(redis_client, key)
      return nil unless redis_client
      redis_client.get(key)
    rescue StandardError
      nil
    end

    # Set Redis key with expiry
    def redis_setex(redis_client, key, expiry_seconds, value)
      return false unless redis_client
      redis_client.setex(key, expiry_seconds, value)
      true
    rescue StandardError
      false
    end

    # Delete Redis key
    def redis_delete(redis_client, key)
      return false unless redis_client
      redis_client.del(key)
      true
    rescue StandardError
      false
    end

    # Delete multiple Redis keys
    def redis_delete_multiple(redis_client, keys)
      return false unless redis_client && keys.any?
      redis_client.del(*keys)
      true
    rescue StandardError
      false
    end

    # Get Redis keys by pattern
    def redis_keys(redis_client, pattern)
      return [] unless redis_client
      redis_client.keys(pattern)
    rescue StandardError
      []
    end

    # Clean up expired keys by pattern
    def cleanup_expired_keys(redis_client, pattern, check_function = nil)
      return 0 unless redis_client

      keys = redis_keys(redis_client, pattern)
      return 0 if keys.empty?

      expired_keys = []
      keys.each do |key|
        if check_function
          # Use custom check function
          expired_keys << key if check_function.call(key)
        else
          # Check TTL
          ttl = redis_client.ttl(key)
          expired_keys << key if ttl <= 0
        end
      end

      return 0 if expired_keys.empty?

      redis_delete_multiple(redis_client, expired_keys)
      expired_keys.length
    rescue StandardError
      0
    end

    # Check Redis connection health
    def redis_healthy?(redis_client)
      return false unless redis_client
      redis_client.ping == "PONG"
    rescue StandardError
      false
    end

    # Validate Redis URL
    def valid_redis_url?(url)
      return false unless url.is_a?(String)
      return false if url.empty?

      begin
        URI.parse(url)
        true
      rescue URI::InvalidURIError
        false
      end
    end

    # Parse Redis URL
    def parse_redis_url(url)
      return {} unless valid_redis_url?(url)

      uri = URI.parse(url)
      {
        scheme: uri.scheme,
        host: uri.host,
        port: uri.port,
        path: uri.path,
        password: uri.password,
        database: uri.path&.sub("/", "")&.to_i || 0
      }
    rescue StandardError
      {}
    end

    # Generate Redis connection options from URL
    def redis_connection_options(url)
      parsed = parse_redis_url(url)
      return {} if parsed.empty?

      options = {
        host: parsed[:host] || "localhost",
        port: parsed[:port] || 6379,
        db: parsed[:database] || 0
      }

      options[:password] = parsed[:password] if parsed[:password]
      options
    end
  end
end
