# frozen_string_literal: true

require 'bcrypt'

module JwtPhantomAuth
  class UserAuthenticator
    def initialize(configuration)
      @config = configuration
    end

    # Authenticate a user with login identifier and password
    def authenticate(login_identifier, password, model_type)
      model_config = @config.model_registry.find_model_by_type(model_type)
      raise ConfigurationError, "Model type '#{model_type}' not found" unless model_config

      user = model_config.find_by_identifier(login_identifier)
      return nil unless user

      authenticate_password(password, user, model_config) ? user : nil
    end

    # Register a new user
    def register(login_identifier, password, model_type, additional_attributes = {})
      model_config = @config.model_registry.find_model_by_type(model_type)
      raise ConfigurationError, "Model type '#{model_type}' not found" unless model_config

      # Check if user already exists
      existing_user = model_config.find_by_identifier(login_identifier)
      raise RegistrationError, "User with this login identifier already exists" if existing_user

      # Create new user
      user_attributes = {
        model_config.login_field => login_identifier,
        model_config.password_field => JwtPhantomAuth.utils.hash_password(password)
      }.merge(additional_attributes)

      # Set payload identifier if not provided
      unless user_attributes[model_config.payload_identifier_field]
        user_attributes[model_config.payload_identifier_field] = JwtPhantomAuth.utils.generate_uuid
      end

      user = model_config.model_class.create!(user_attributes)

      user
    rescue ActiveRecord::RecordInvalid => e
      raise RegistrationError, "Validation failed: #{e.message}"
    end

    # Find a user by ID
    def find_user(id, model_type)
      model_config = @config.model_registry.find_model_by_type(model_type)
      return nil unless model_config

      model_config.model_class.find_by(id: id)
    end

    # Find a user by login identifier
    def find_user_by_identifier(login_identifier, model_type)
      model_config = @config.model_registry.find_model_by_type(model_type)
      return nil unless model_config

      model_config.find_by_identifier(login_identifier)
    end

    # Reset password for a user
    def reset_password(login_identifier, new_password, model_type)
      model_config = @config.model_registry.find_model_by_type(model_type)
      raise ConfigurationError, "Model type '#{model_type}' not found" unless model_config

      user = model_config.find_by_identifier(login_identifier)
      raise UserNotFoundError, "User not found" unless user

      # Hash the new password
      hashed_password = JwtPhantomAuth.utils.hash_password(new_password)
      user.update!(model_config.password_field => hashed_password)

      user
    end

    # Generate password reset token
    def generate_password_reset_token(login_identifier, model_type)
      model_config = @config.model_registry.find_model_by_type(model_type)
      raise ConfigurationError, "Model type '#{model_type}' not found" unless model_config

      user = model_config.find_by_identifier(login_identifier)
      raise UserNotFoundError, "User not found" unless user

      token = JwtPhantomAuth.utils.generate_secure_string(32)
      payload_identifier = model_config.get_payload_identifier(user)

      # Store token in Redis with 1 hour expiry
      redis_key = JwtPhantomAuth.utils.password_reset_key(model_type, payload_identifier)
      JwtPhantomAuth.utils.redis_setex(@config.redis_client, redis_key, 3600, token)

      token
    end

    # Verify password reset token
    def verify_password_reset_token(login_identifier, token, model_type)
      model_config = @config.model_registry.find_model_by_type(model_type)
      raise ConfigurationError, "Model type '#{model_type}' not found" unless model_config

      user = model_config.find_by_identifier(login_identifier)
      raise UserNotFoundError, "User not found" unless user

      payload_identifier = model_config.get_payload_identifier(user)
      redis_key = JwtPhantomAuth.utils.password_reset_key(model_type, payload_identifier)
      stored_token = JwtPhantomAuth.utils.redis_get(@config.redis_client, redis_key)

      return false unless stored_token && JwtPhantomAuth.utils.secure_compare(token, stored_token)

      # Clear the token after successful verification
      JwtPhantomAuth.utils.redis_delete(@config.redis_client, redis_key)
      true
    end

    # Clear password reset token
    def clear_password_reset_token(login_identifier, model_type)
      model_config = @config.model_registry.find_model_by_type(model_type)
      return unless model_config

      user = model_config.find_by_identifier(login_identifier)
      return unless user

      payload_identifier = model_config.get_payload_identifier(user)
      redis_key = JwtPhantomAuth.utils.password_reset_key(model_type, payload_identifier)
      JwtPhantomAuth.utils.redis_delete(@config.redis_client, redis_key)
    end

    private

    def authenticate_password(password, user, model_config)
      hashed_password = user.send(model_config.password_field)

      JwtPhantomAuth.utils.verify_password(password, hashed_password)
    end
  end
end
