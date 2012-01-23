require 'rubygems'
require 'rack'
require 'rack/auth/abstract/handler'
require 'rack/auth/abstract/request'
require 'auth'

module Auth
  class Middleware < Rack::Auth::AbstractHandler

    def initialize(app, realm=nil, options={}, &authenticator)
      super(app, realm, &authenticator)
      @options = options
    end

    def call(env)
      auth = Request.new(env)

      unless @options[:allow_unauthenticated]
        return unauthorized unless auth.provided?
        return bad_request unless auth.bearer?
      end

      if auth.provided? && valid?(auth)
        env['REMOTE_USER'] = auth.account_id
        return @app.call(env)
      end

      if @options[:allow_unauthenticated]
        res = @app.call(env)
        return [res[0],
                res[1].merge('WWW-Authenticate' => challenge),
                res[2]]
      else
        unauthorized
      end
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

        def provided?
          super || request.params['access_token']
        end

        def parts
          authorization_key ? super : ['Bearer', nil]
        end

        def access_token
          @access_token ||= params ? params.unpack("m*").first :
                                     request.params['access_token']
        end

        def account_id
          @account_id ||= Auth.validate_token(access_token)
        end
      end

  end
end
