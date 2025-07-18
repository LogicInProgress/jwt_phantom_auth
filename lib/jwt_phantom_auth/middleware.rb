# frozen_string_literal: true

module JwtPhantomAuth
  # JWT Phantom Auth Middleware
  #
  # Usage:
  #   # In config/application.rb
  #   config.middleware.use JwtPhantomAuth::Middleware, skip_paths: ['/auth', '/health']
  #
  #   # In controllers
  #   def current_user
  #     request.env['jwt_phantom_auth.user']
  #   end
  class Middleware
    def initialize(app, configuration)
      @app = app
      @config = configuration
    end

    def call(env)
      request = Rack::Request.new(env)

      # Skip authentication for certain paths
      return @app.call(env) if skip_authentication?(request)

      # Extract token from request
      token = extract_token_from_request(request)
      return unauthorized_response unless token

      # Authenticate the token
      user = authenticate_token(token)
      return unauthorized_response unless user

      # Add user to request environment
      env['jwt_phantom_auth.user'] = user
      env['jwt_phantom_auth.token'] = token

      @app.call(env)
    end

    private

    def skip_authentication?(request)
      # Skip authentication for public endpoints
      public_paths = ['/health', '/status', '/ping']
      public_paths.any? { |path| request.path.start_with?(path) }
    end

    def extract_token_from_request(request)
      # Try to get token from Authorization header
      auth_header = request.env['HTTP_AUTHORIZATION']
      if auth_header && auth_header.start_with?('Bearer ')
        return auth_header.sub('Bearer ', '')
      end

      # Try to get token from query parameter
      request.params['token']
    end

    def authenticate_token(token)
      # Check if it's a phantom token
      if JwtPhantomAuth.utils.phantom_token?(token)
        authenticate_phantom_token(token)
      elsif JwtPhantomAuth.utils.jwt_token?(token)
        authenticate_jwt_token(token)
      else
        nil
      end
    end

    def authenticate_phantom_token(phantom_token)
      begin
        # Exchange phantom token for access token
        result = JwtPhantomAuth.phantom_token_manager.exchange_phantom_token(phantom_token)
        
        # Extract payload identifier and model type from the exchange result
        payload_identifier = extract_payload_identifier_from_result(result)
        model_type = extract_model_type_from_result(result)

        # Find user by payload identifier and model type
        find_user_by_payload_identifier_and_type(payload_identifier, model_type)
      rescue PhantomTokenError, TokenExpiredError, InvalidTokenError
        nil
      end
    end

    def authenticate_jwt_token(jwt_token)
      begin
        # Decode and validate the JWT token
        payload = JwtPhantomAuth.token_manager.decode_token(jwt_token)
        
        # Extract payload identifier and model type from the JWT payload
        payload_identifier = extract_payload_identifier_from_payload(payload)
        model_type = extract_model_type_from_payload(payload)

        # Find user by payload identifier and model type
        find_user_by_payload_identifier_and_type(payload_identifier, model_type)
      rescue TokenExpiredError, InvalidTokenError
        nil
      end
    end

    def extract_payload_identifier_from_result(result)
      # Try different possible keys for payload identifier
      result[:payload_identifier] || result['payload_identifier']
    end

    def extract_model_type_from_result(result)
      # Try different possible keys for model type
      result[:model_type] || result['model_type']
    end

    def extract_payload_identifier_from_payload(payload)
      # Try different possible keys for payload identifier
      payload['payload_identifier'] || payload['user_id'] || payload['email']
    end

    def extract_model_type_from_payload(payload)
      payload['model_type']
    end

    def find_user_by_payload_identifier_and_type(payload_identifier, model_type)
      return nil unless payload_identifier && model_type

      model_config = @config.model_registry.find_model_by_type(model_type)
      return nil unless model_config

      model_config.find_by_payload_identifier(payload_identifier)
    end

    def unauthorized_response
      [
        401,
        { 'Content-Type' => 'application/json' },
        [{ error: 'Unauthorized', message: 'Invalid or missing authentication token' }.to_json]
      ]
    end
  end

  class Engine < ::Rails::Engine
    # Rails initializer that automatically adds the middleware
    #
    # This initializer runs during Rails boot and adds the JWT Phantom Auth
    # middleware to the middleware stack with default configuration.
    initializer "jwt_phantom_auth.middleware" do |app|
      app.config.middleware.use JwtPhantomAuth::Middleware, skip_paths: ["/auth", "/health"]
    end
  end
end
