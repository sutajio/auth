require 'rubygems'
require 'rack'
require 'rack/auth/abstract/handler'
require 'rack/auth/abstract/request'
require 'auth'

module Auth
  class Middleware < Rack::Auth::AbstractHandler

    def call(env)
      auth = Request.new(env)

      return unauthorized unless auth.provided?
      return bad_request unless auth.bearer?

      if valid?(auth)
        env['REMOTE_USER'] = auth.account_id
        return @app.call(env)
      end

      unauthorized
    end

    private

      def challenge
        'Bearer realm="%s"' % realm
      end

      def valid?(auth)
        auth.account_id ? true : false
      end

      class Request < Rack::Auth::AbstractRequest
        def bearer?
          :bearer == scheme
        end

        def access_token
          @access_token ||= params.unpack("m*").first
        end

        def account_id
          @account_id ||= Auth.validate_token(access_token)
        end
      end

  end
end
