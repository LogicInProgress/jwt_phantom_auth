# frozen_string_literal: true

require 'bcrypt'

module JwtPhantomAuth
  class UserAuthenticator
    def initialize(configuration)
      @config = configuration
    end

    # Authenticate user with email/username and password
    def authenticate(identifier, password)
      user = find_user_by_identifier(identifier)
      return nil unless user
      return nil unless valid_password?(user, password)
      
      user
    end

    # Register a new user
    def register(user_params, model_name = nil)
      model_config = get_model_config(model_name)
      user = model_config.model_class.new(user_params)
      
      # Hash password if present
      if user.respond_to?(model_config.password_field) && user.send(model_config.password_field).present?
        user.send("#{model_config.password_field}=", hash_password(user.send(model_config.password_field)))
      end
      
      user.save ? user : nil
    end

    # Find user by ID
    def find_user(user_id, model_name = nil)
      model_config = get_model_config(model_name)
      model_config.model_class.find_by(id: user_id)
    end

    # Find user by identifier (email/username)
    def find_user_by_identifier(identifier, model_name = nil)
      model_config = get_model_config(model_name)
      model_config.model_class.send(model_config.find_method, model_config.identifier_field => identifier)
    end

    # Update user password
    def update_password(user, new_password)
      model_config = @config.config_for_object(user)
      user.send("#{model_config.password_field}=", hash_password(new_password))
      user.save
    end

    # Verify password without updating
    def verify_password(user, password)
      model_config = @config.config_for_object(user)
      return false unless user.respond_to?(model_config.password_field)
      
      stored_password = user.send(model_config.password_field)
      return false unless stored_password.present?
      
      BCrypt::Password.new(stored_password) == password
    end

    # Generate password reset token
    def generate_password_reset_token(user)
      token = SecureRandom.hex(32)
      redis_key = "password_reset:#{user.id}"
      
      # Store token with 1 hour expiry
      @config.redis_client.setex(redis_key, 3600, token)
      
      token
    end

    # Verify password reset token
    def verify_password_reset_token(user_id, token)
      redis_key = "password_reset:#{user_id}"
      stored_token = @config.redis_client.get(redis_key)
      
      return false unless stored_token == token
      
      # Delete token after verification
      @config.redis_client.del(redis_key)
      true
    end

    # Reset password using token
    def reset_password(user_id, token, new_password)
      return false unless verify_password_reset_token(user_id, token)
      
      user = find_user(user_id)
      return false unless user
      
      update_password(user, new_password)
    end

    # Check if user exists
    def user_exists?(identifier)
      find_user_by_identifier(identifier).present?
    end

    # Get user info for token generation
    def get_user_info(user)
      model_config = @config.config_for_object(user)
      
      # Try to use custom token payload method if available
      if user.respond_to?(model_config.token_payload_method)
        return user.send(model_config.token_payload_method)
      end
      
      # Fallback to default payload
      {
        id: user.id,
        email: user.send(model_config.identifier_field),
        created_at: user.created_at,
        updated_at: user.updated_at
      }
    end

    private

    def get_model_config(model_name)
      if model_name
        @config.get_model_config(model_name)
      else
        @config.model_registry.default_model
      end
    end

    def valid_password?(user, password)
      verify_password(user, password)
    end

    def hash_password(password)
      BCrypt::Password.create(password)
    end
  end
end 