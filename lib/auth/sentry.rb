module Auth
  class Sentry
    class User
      def initialize(id); @id = id; end
      def id; @id; end
    end

    def initialize(request)
      @request = request
    end

    def authenticate!
      if Auth.authenticate_account(@request.params['username'], @request.params['password'])
        @user_id = @request.params['username']
      else
        raise AuthException, 'Invalid username or password'
      end
    end

    def user
      @user_id ? User.new(@user_id) : nil
    end
  end
end
