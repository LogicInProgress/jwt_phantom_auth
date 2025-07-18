# frozen_string_literal: true

require 'openssl'
require 'bcrypt'

module JwtPhantomAuth
  # Security-related utility methods
  module SecurityUtils
    # Generate a secure random string
    def generate_secure_random_string(length = 32)
      SecureRandom.urlsafe_base64(length)
    end

    # Generate a secure random hex string
    def generate_secure_random_hex(length = 32)
      SecureRandom.hex(length)
    end

    # Generate a secure random UUID
    def generate_secure_uuid
      SecureRandom.uuid
    end

    # Hash password using BCrypt
    def hash_password(password, cost = 12)
      return nil if blank?(password)
      BCrypt::Password.create(password, cost: cost)
    end

    # Verify password against hash
    def verify_password(password, hash)
      return false if blank?(password) || blank?(hash)

      BCrypt::Password.new(hash) == password
    rescue BCrypt::Errors::InvalidHash
      false
    end

    # Generate a secure salt
    def generate_salt(length = 16)
      SecureRandom.hex(length)
    end

    # Hash string using SHA256
    def sha256_hash(string)
      return nil if blank?(string)
      Digest::SHA256.hexdigest(string)
    end

    # Generate HMAC signature
    def generate_hmac(data, secret_key, algorithm = 'sha256')
      return nil if blank?(data) || blank?(secret_key)

      digest = case algorithm.downcase
               when 'sha1'
                 OpenSSL::Digest.new('sha1')
               when 'sha256'
                 OpenSSL::Digest.new('sha256')
               when 'sha512'
                 OpenSSL::Digest.new('sha512')
               else
                 OpenSSL::Digest.new('sha256')
               end

      OpenSSL::HMAC.hexdigest(digest, secret_key, data)
    end

    # Verify HMAC signature
    def verify_hmac(data, signature, secret_key, algorithm = 'sha256')
      expected_signature = generate_hmac(data, secret_key, algorithm)
      secure_compare(signature, expected_signature)
    end

    # Secure string comparison (constant-time)
    def secure_compare(string1, string2)
      return false unless string1.is_a?(String) && string2.is_a?(String)
      return false if string1.length != string2.length

      result = 0
      string1.bytes.each_with_index do |byte, i|
        result |= byte ^ string2.bytes[i]
      end
      result.zero?
    end

    # Generate a secure token
    def generate_secure_token(length = 32)
      SecureRandom.urlsafe_base64(length, padding: false)
    end

    # Generate a secure API key
    def generate_api_key(prefix = 'jwt_phantom_')
      "#{prefix}#{SecureRandom.urlsafe_base64(32, padding: false)}"
    end

    # Generate a secure session ID
    def generate_session_id
      SecureRandom.urlsafe_base64(32, padding: false)
    end

    # Generate a secure nonce
    def generate_nonce(length = 16)
      SecureRandom.hex(length)
    end

    # Generate a secure challenge
    def generate_challenge(length = 32)
      SecureRandom.urlsafe_base64(length, padding: false)
    end

    # Hash sensitive data for logging
    def hash_sensitive_data(data, algorithm = 'sha256')
      return '***' if blank?(data)
      digest = case algorithm.downcase
               when 'sha1'
                 Digest::SHA1.hexdigest(data.to_s)
               when 'sha256'
                 Digest::SHA256.hexdigest(data.to_s)
               when 'sha512'
                 Digest::SHA512.hexdigest(data.to_s)
               else
                 Digest::SHA256.hexdigest(data.to_s)
               end
      digest[0, 8] # Return first 8 characters
    end

    # Mask sensitive data for display
    def mask_sensitive_data(data, visible_chars = 4, mask_char = '*')
      return '***' if blank?(data)

      string = data.to_s
      return '***' if string.length <= visible_chars

      "#{string[0, visible_chars]}#{mask_char * (string.length - visible_chars)}"
    end

    # Check if password meets security requirements
    def password_meets_requirements?(password, min_length = 8, require_special = true)
      return false if blank?(password)
      return false if password.length < min_length

      if require_special
        # Check for at least one uppercase, lowercase, digit, and special character
        has_upper = password.match?(/[A-Z]/)
        has_lower = password.match?(/[a-z]/)
        has_digit = password.match?(/\d/)
        has_special = password.match?(/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/)

        has_upper && has_lower && has_digit && has_special
      else
        # Just check length
        true
      end
    end

    # Calculate password strength score
    def password_strength_score(password)
      return 0 if blank?(password)

      score = 0
      score += 1 if password.length >= 8
      score += 1 if password.length >= 12
      score += 1 if password.match?(/[A-Z]/)
      score += 1 if password.match?(/[a-z]/)
      score += 1 if password.match?(/\d/)
      score += 1 if password.match?(/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/)
      score += 1 if password.match?(/[^A-Za-z0-9!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/)

      score
    end

    # Get password strength description
    def password_strength_description(password)
      score = password_strength_score(password)

      case score
      when 0..2
        'Very Weak'
      when 3..4
        'Weak'
      when 5..6
        'Medium'
      when 7..8
        'Strong'
      else
        'Very Strong'
      end
    end

    # Generate a secure checksum for data
    def generate_checksum(data, algorithm = 'sha256')
      return nil if blank?(data)

      digest = case algorithm.downcase
               when 'md5'
                 Digest::MD5.hexdigest(data.to_s)
               when 'sha1'
                 Digest::SHA1.hexdigest(data.to_s)
               when 'sha256'
                 Digest::SHA256.hexdigest(data.to_s)
               when 'sha512'
                 Digest::SHA512.hexdigest(data.to_s)
               else
                 Digest::SHA256.hexdigest(data.to_s)
               end
    end

    # Verify checksum
    def verify_checksum(data, expected_checksum, algorithm = 'sha256')
      actual_checksum = generate_checksum(data, algorithm)
      secure_compare(actual_checksum, expected_checksum)
    end

    # Generate a secure fingerprint
    def generate_fingerprint(data, algorithm = 'sha256')
      generate_checksum(data, algorithm)
    end

    # Sanitize input for SQL injection prevention
    def sanitize_sql_input(input)
      return nil if input.nil?

      # Basic SQL injection prevention
      string = input.to_s
      string.gsub(/['";\\]/, '')
    end

    # Sanitize input for XSS prevention
    def sanitize_xss_input(input)
      return nil if input.nil?

      # Basic XSS prevention
      string = input.to_s
      string.gsub(/[<>]/, '')
    end

    # Check if string contains potentially dangerous content
    def contains_dangerous_content?(string)
      return false if blank?(string)

      dangerous_patterns = [
        /<script/i,
        /javascript:/i,
        /on\w+\s*=/i,
        /data:text\/html/i,
        /vbscript:/i,
        /expression\s*\(/i
      ]

      dangerous_patterns.any? { |pattern| string.match?(pattern) }
    end

    # Sanitize dangerous content
    def sanitize_dangerous_content(string)
      return nil if blank?(string)

      sanitized = string.to_s
      sanitized = sanitized.gsub(/<script[^>]*>.*?<\/script>/mi, '')
      sanitized = sanitized.gsub(/javascript:/i, '')
      sanitized = sanitized.gsub(/on\w+\s*=/i, '')
      sanitized = sanitized.gsub(/data:text\/html/i, '')
      sanitized = sanitized.gsub(/vbscript:/i, '')
      sanitized = sanitized.gsub(/expression\s*\(/i, '')

      sanitized
    end

    # Check if data contains sensitive information
    def contains_sensitive_data?(data)
      return false if blank?(data)

      sensitive_patterns = [
        /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/, # Credit card
        /\b\d{3}-\d{2}-\d{4}\b/, # SSN
        /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/, # Email
        /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/, # IP address
        /\bpassword\s*[:=]\s*\S+/i, # Password in text
        /\bsecret\s*[:=]\s*\S+/i, # Secret in text
        /\bkey\s*[:=]\s*\S+/i # Key in text
      ]

      sensitive_patterns.any? { |pattern| data.to_s.match?(pattern) }
    end

    # Sanitize sensitive data
    def sanitize_sensitive_data(data)
      return data if blank?(data)

      sanitized = data.to_s
      sanitized = sanitized.gsub(/\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/, '[CREDIT_CARD]')
      sanitized = sanitized.gsub(/\b\d{3}-\d{2}-\d{4}\b/, '[SSN]')
      sanitized = sanitized.gsub(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/, '[EMAIL]')
      sanitized = sanitized.gsub(/\bpassword\s*[:=]\s*\S+/i, 'password: [REDACTED]')
      sanitized = sanitized.gsub(/\bsecret\s*[:=]\s*\S+/i, 'secret: [REDACTED]')
      sanitized = sanitized.gsub(/\bkey\s*[:=]\s*\S+/i, 'key: [REDACTED]')

      sanitized
    end
  end
end
