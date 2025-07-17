# frozen_string_literal: true

module JwtPhantomAuth
  class ModelRegistry
    class ModelConfig
      attr_accessor :model_class,
                    :identifier_field,
                    :password_field,
                    :token_payload_method,
                    :authentication_method,
                    :find_method

      def initialize(model_class, options = {})
        @model_class = model_class
        @identifier_field = options[:identifier_field] || :email
        @password_field = options[:password_field] || :password
        @token_payload_method = options[:token_payload_method] || :to_token_payload
        @authentication_method = options[:authentication_method] || :authenticate
        @find_method = options[:find_method] || :find_by
      end

      def validate!
        raise ConfigurationError, "Model class #{model_class} is required" if model_class.nil?
        raise ConfigurationError, "Model class #{model_class} must be a Class" unless model_class.is_a?(Class)
      end
    end

    def initialize
      @models = {}
      @default_model = nil
    end

    # Register a model with its configuration
    def register(model_name, model_class, options = {})
      config = ModelConfig.new(model_class, options)
      config.validate!
      
      @models[model_name.to_s] = config
      @default_model = model_name.to_s if @default_model.nil?
      
      config
    end

    # Set the default model
    def default_model=(model_name)
      raise ConfigurationError, "Model '#{model_name}' not registered" unless @models.key?(model_name.to_s)
      @default_model = model_name.to_s
    end

    # Get the default model configuration
    def default_model
      @models[@default_model]
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

    # Validate all registered models
    def validate!
      raise ConfigurationError, 'At least one model must be registered' if @models.empty?
      raise ConfigurationError, 'Default model must be set' if @default_model.nil?
      
      @models.each do |name, config|
        config.validate!
      end
    end

    # Get model configuration for an object
    def config_for_object(object)
      return default_model unless object.respond_to?(:class)
      
      config = find_model_by_class(object.class)
      config || default_model
    end
  end
end 