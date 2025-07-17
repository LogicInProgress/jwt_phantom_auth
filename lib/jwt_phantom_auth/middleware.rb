# frozen_string_literal: true

module JwtPhantomAuth
  class Middleware
    def initialize(app, options = {})
      @app = app
      @options = options
      @config = JwtPhantomAuth.configuration
    end

    def call(env)
      request = Rack::Request.new(env)
      
      # Skip authentication for certain paths
      return @app.call(env) if skip_authentication?(request)
      
      # Extract token from request
      token = extract_token(request)
      
      if token
        begin
          # Handle phantom token or regular JWT token
          user = authenticate_token(token)
          env['jwt_phantom_auth.user'] = user
          env['jwt_phantom_auth.token'] = token
        rescue JwtPhantomAuth::TokenExpiredError, JwtPhantomAuth::InvalidTokenError => e
          return unauthorized_response(e.message)
        rescue JwtPhantomAuth::PhantomTokenError => e
          return unauthorized_response(e.message)
        end
      end
      
      @app.call(env)
    end

    private

    def skip_authentication?(request)
      skip_paths = @options[:skip_paths] || []
      skip_paths.any? { |path| request.path.start_with?(path) }
    end

    def extract_token(request)
      # Check Authorization header
      auth_header = request.env['HTTP_AUTHORIZATION']
      if auth_header && auth_header.start_with?('Bearer ')
        return auth_header.split(' ').last
      end
      
      # Check for phantom token in custom header
      phantom_header = request.env['HTTP_X_PHANTOM_TOKEN']
      return phantom_header if phantom_header
      
      # Check query parameter
      request.params['token']
    end

    def authenticate_token(token)
      if @config.phantom_tokens_enabled? && is_phantom_token?(token)
        authenticate_phantom_token(token)
      else
        authenticate_jwt_token(token)
      end
    end

    def is_phantom_token?(token)
      # Phantom tokens are 64 character hex strings
      token.length == 64 && token.match?(/\A[0-9a-f]+\z/i)
    end

    def authenticate_phantom_token(phantom_token)
      result = JwtPhantomAuth.phantom_token_manager.exchange_phantom_token(phantom_token)
      user = JwtPhantomAuth.user_authenticator.find_user(result[:user_id])
      raise JwtPhantomAuth::UserNotFoundError, 'User not found' unless user
      user
    end

    def authenticate_jwt_token(token)
      payload = JwtPhantomAuth.token_manager.decode_token(token)
      raise JwtPhantomAuth::InvalidTokenError, 'Invalid token type' unless payload['token_type'] == 'access'
      
      user = JwtPhantomAuth.user_authenticator.find_user(payload['user_id'])
      raise JwtPhantomAuth::UserNotFoundError, 'User not found' unless user
      user
    end

    def unauthorized_response(message)
      [
        401,
        { 'Content-Type' => 'application/json' },
        [{ error: 'Unauthorized', message: message }.to_json]
      ]
    end
  end

  # Rails Engine for easy integration
  class Engine < ::Rails::Engine
    initializer 'jwt_phantom_auth.middleware' do |app|
      app.config.middleware.use JwtPhantomAuth::Middleware, skip_paths: ['/auth', '/health']
    end
  end
end 