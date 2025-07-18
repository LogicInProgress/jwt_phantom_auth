# frozen_string_literal: true

# JWT Phantom Auth Utilities
# This file serves as the main entry point for essential utility methods

require_relative "utils/token_utils"
require_relative "utils/redis_utils"
require_relative "utils/security_utils"

module JwtPhantomAuth
  # Main utility module that provides access to essential utility methods
  module Utils
    extend TokenUtils
    extend RedisUtils
    extend SecurityUtils

    # Essential utility class methods
    class << self
      # Check if a value is blank (nil, empty string, or whitespace)
      def blank?(value)
        value.nil? || (value.respond_to?(:empty?) && value.empty?) || (value.is_a?(String) && value.strip.empty?)
      end

      # Check if a value is present (not blank)
      def present?(value)
        !blank?(value)
      end

      # Generate a secure random string
      def generate_secure_string(length = 32)
        SecureRandom.urlsafe_base64(length)
      end

      # Generate a UUID
      def generate_uuid
        SecureRandom.uuid
      end

      # Generate a random hex string
      def random_hex(length = 32)
        SecureRandom.hex(length)
      end

      # Check if a string is a valid email
      def valid_email?(email)
        email_regex = /\A[\w+\-.]+@[a-z\d\-]+(\.[a-z\d\-]+)*\.[a-z]+\z/i
        email_regex.match?(email.to_s)
      end

      # Check if a string is a valid UUID
      def valid_uuid?(uuid)
        uuid_regex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
        uuid_regex.match?(uuid.to_s)
      end

      # Safely convert a value to integer
      def safe_to_i(value, default = 0)
        Integer(value)
      rescue ArgumentError, TypeError
        default
      end

      # Safely convert a value to boolean
      def safe_to_bool(value)
        case value
        when true, 'true', '1', 1
          true
        when false, 'false', '0', 0, nil
          false
        else
          false
        end
      end

      # Deep merge two hashes
      def deep_merge(hash1, hash2)
        hash1.merge(hash2) do |key, val1, val2|
          if val1.is_a?(Hash) && val2.is_a?(Hash)
            deep_merge(val1, val2)
          else
            val2
          end
        end
      end

      # Convert hash keys to symbols
      def symbolize_keys(hash)
        hash.transform_keys(&:to_sym)
      end

      # Convert hash keys to strings
      def stringify_keys(hash)
        hash.transform_keys(&:to_s)
      end

      # Truncate a string to a specified length
      def truncate(string, length = 50, omission = '...')
        return string if string.length <= length
        "#{string[0, length - omission.length]}#{omission}"
      end

      # Check if a string is a valid JSON
      def valid_json?(string)
        JSON.parse(string)
        true
      rescue JSON::ParserError
        false
      end

      # Parse JSON safely
      def safe_parse_json(string, default = {})
        JSON.parse(string)
      rescue JSON::ParserError
        default
      end

      # Convert object to JSON safely
      def safe_to_json(object, default = '{}')
        object.to_json
      rescue StandardError
        default
      end

      # Check if a string is a valid base64
      def valid_base64?(string)
        Base64.strict_decode64(string)
        true
      rescue ArgumentError
        false
      end

      # Encode string to base64
      def encode_base64(string)
        Base64.strict_encode64(string)
      end

      # Decode base64 string
      def decode_base64(string)
        Base64.strict_decode64(string)
      end

      # Check if a string is a valid hex
      def valid_hex?(string)
        string.match?(/^[0-9a-fA-F]+$/)
      end

      # Convert hex string to bytes
      def hex_to_bytes(hex_string)
        [hex_string].pack('H*')
      end

      # Convert bytes to hex string
      def bytes_to_hex(bytes)
        bytes.unpack('H*').first
      end

      # Check if a string is a valid IP address
      def valid_ip?(ip)
        IPAddr.new(ip)
        true
      rescue IPAddr::InvalidAddressError
        false
      end

      # Get client IP from request
      def client_ip(request)
        request.env['HTTP_X_FORWARDED_FOR']&.split(',')&.first ||
          request.env['HTTP_X_REAL_IP'] ||
          request.env['REMOTE_ADDR'] ||
          'unknown'
      end

      # Check if request is from localhost
      def localhost?(request)
        ip = client_ip(request)
        ip == '127.0.0.1' || ip == '::1' || ip == 'localhost'
      end

      # Check if request is from private network
      def private_network?(request)
        ip = client_ip(request)
        return false unless valid_ip?(ip)

        ip_addr = IPAddr.new(ip)
        private_ranges = [
          IPAddr.new('10.0.0.0/8'),
          IPAddr.new('172.16.0.0/12'),
          IPAddr.new('192.168.0.0/16'),
          IPAddr.new('fc00::/7')
        ]

        private_ranges.any? { |range| range.include?(ip_addr) }
      rescue IPAddr::InvalidAddressError
        false
      end
    end
  end
end
