module Auth
  class Sentry
    class User
      def initialize(id); @id = id; end
      def id; @id; end
    end

    def initialize(request)
      @request = request
    end

    def authenticate!(domain=:default)
      case domain.to_sym
      when :client
        @client = Auth.authenticate_client(@request.params['client_id'], @request.params['client_secret'])
        unless @client
          raise AuthException, 'Invalid client'
        end
      else
        if Auth.authenticate_account(@request.params['username'], @request.params['password'])
          @user = User.new(@request.params['username'])
        else
          raise AuthException, 'Invalid username or password'
        end
      end
    end

    def user(domain=:default)
      case domain.to_sym
      when :client
        @client ? @client : nil
      else
        @user ? @user : nil
      end
    end
  end
end
