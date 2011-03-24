module Auth
  class AuthException < RuntimeError; end
  class InvalidRequest < AuthException; end
  class UnauthorizedClient < AuthException; end
  class AccessDenied < AuthException; end
  class UnsupportedResponseType < AuthException; end
  class InvalidScope < AuthException; end
end
