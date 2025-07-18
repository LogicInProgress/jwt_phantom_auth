# frozen_string_literal: true

module JwtPhantomAuth
  class ModelRegistry
    class ModelConfig
      attr_accessor :model_class, :model_name,
                    :login_field, :password_field,
                    :find_method,
                    :token_payload_method,
                    :payload_identifier_field,
                    :payload_identifier_method,

      def initialize(model_class, options = {})
        @model_class = model_class
        @model_name = options[:model_name] || model_class.name.underscore.to_sym

        # Fields for registering the user
        @login_field = options[:login_field] || :email
        @password_field = options[:password_field] || :password

        # Fields for token payload and finding the user
        @token_payload_method = options[:token_payload_method] || :to_token_payload
        @find_method = options[:find_method] || :find_by

        # Configure which field to use in JWT payload for user identification
        @payload_identifier_field = options[:payload_identifier_field] || :uuid
        @payload_identifier_method = options[:payload_identifier_method] || :find_by_uuid
      end

      def validate!
        raise ConfigurationError, "Model class #{model_class} is required" if model_class.nil?
        raise ConfigurationError, "Model class #{model_class} must be a Class" unless model_class.is_a?(Class)

        # Validate that the login field exists on the model
        unless model_class.column_names.include?(login_field.to_s)
          raise ConfigurationError, "Login field '#{login_field}' not found on #{model_class}"
        end

        # Validate that the payload identifier field exists on the model
        unless model_class.column_names.include?(payload_identifier_field.to_s)
          raise ConfigurationError, "Payload identifier field '#{payload_identifier_field}' not found on #{model_class}"
        end

        # Validate that the find method exists on the model
        unless model_class.respond_to?(payload_identifier_method)
          raise ConfigurationError, "Payload identifier method '#{payload_identifier_method}' not found on #{model_class}"
        end

        # Validate that the find_by_identifier method exists (or can be created)
        unless model_class.respond_to?(:find_by_identifier)
          # Try to create a dynamic find_by method if it doesn't exist
          unless model_class.respond_to?("find_by_#{login_field}")
            raise ConfigurationError, "Model #{model_class} must have a find_by_identifier method or respond to find_by_#{login_field}"
          end
        end
      end

      # Find a user by their login identifier (email, username, etc.)
      def find_by_identifier(identifier)
        if model_class.respond_to?(:find_by_identifier)
          model_class.find_by_identifier(identifier)
        else
          # Fallback to dynamic find_by method
          model_class.send("find_by_#{login_field}", identifier)
        end
      end

      # Get the payload identifier value for a user object
      # This is the value that will be stored in the JWT token
      def get_payload_identifier(user)
        if user.respond_to?(payload_identifier_field)
          user.send(payload_identifier_field)
        else
          raise ConfigurationError, "User object does not respond to '#{payload_identifier_field}'"
        end
      end

      # Find a user by the payload identifier
      # This is used to look up users from JWT token payloads
      def find_by_payload_identifier(identifier)
        model_class.send(payload_identifier_method, payload_identifier_field => identifier)
      end

      # Get model type for payload inclusion
      # This helps distinguish between different models with same identifier values
      def get_model_type
        model_name.to_s
      end
    end

    def initialize
      @models = {}
    end

    # Register a model with its configuration
    def register(model_name, model_class, options = {})
      # Add model_name to options for the ModelConfig
      options[:model_name] = model_name
      config = ModelConfig.new(model_class, options)

      # Validate model registration
      config.validate!

      @models[model_name.to_s] = config
      config
    end

    # Get a specific model configuration
    def get_model(model_name)
      @models[model_name.to_s]
    end

    # Get all registered models
    def all_models
      @models
    end

    # Check if a model is registered
    def model_registered?(model_name)
      @models.key?(model_name.to_s)
    end

    # Get model by class
    def find_model_by_class(model_class)
      @models.find { |_, config| config.model_class == model_class }&.last
    end

    # Find model by type name
    def find_model_by_type(model_type)
      @models[model_type.to_s]
    end

    # Validate all registered models
    def validate!
      raise ConfigurationError, 'At least one model must be registered' if @models.empty?

      @models.each do |name, config|
        config.validate!
      end
    end

    # Get model configuration for an object
    def config_for_object(object)
      return nil unless object.respond_to?(:class)

      find_model_by_class(object.class)
    end

    # Find user by payload identifier and model type
    # This ensures we look up the correct model even if identifiers are the same
    def find_user_by_payload_identifier_and_type(payload_identifier, model_type)
      config = find_model_by_type(model_type)
      return nil unless config

      config.find_by_payload_identifier(payload_identifier)
    end
  end
end
