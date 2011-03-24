module Auth
  class Sentry
    class User
      def initialize(id); @id = id; end
      def id; @id; end
    end

    def authenticate!; end
    def user; @user_id ? User.new(@user_id) : nil; end
  end

  class DummySentry < Sentry
    def authenticate!
      @user_id = 'dummy'
    end
  end

  class RemoteSentry < Sentry
    def initialize(url)
      @url = url
    end

    def authenticate!
      raise NotImplemented
    end
  end
end
