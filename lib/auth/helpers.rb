require 'base64'
require 'digest/sha2'
require 'openssl'

begin
  require 'securerandom'
rescue LoadError
end

module Auth
  module Helpers

    # Base64 encode a string in a way that is safe to include in a URL
    def urlsafe_base64_encode(str)
      Base64.encode64(str).gsub('/','-').gsub('+','_').gsub('=','').strip
    end

    # Decode a string that has been encoded with the urlsafe_base64_encode method
    def urlsafe_base64_decode(str)
      Base64.decode64(str.gsub('-','/').gsub('_','+') + '==')
    end

    # Generate a unique cryptographically secure secret
    def generate_secret
      if defined?(SecureRandom)
        SecureRandom.urlsafe_base64(32)
      else
        urlsafe_base64(
          Digest::SHA256.digest("#{Time.now}-#{Time.now.usec}-#{$$}-#{rand}")
        )
      end
    end

    # Generate a crypthographically secure signature
    def hmac(key, data)
      OpenSSL::HMAC.hexdigest(OpenSSL::Digest::Digest.new('sha1'), key, data)
    end

    # Obfuscate a password using a salt and a cryptographic hash function
    def encrypt_password(password, salt, hash)
      case hash.to_s
      when 'sha256'
        Digest::SHA256.hexdigest("#{password}-#{salt}")
      else
        raise 'Unsupported hash algorithm'
      end
    end

    # Given a Ruby object, returns a string suitable for storage in a
    # queue.
    def encode(object)
      object.to_json
    end

    # Given a string, returns a Ruby object.
    def decode(object)
      return unless object
      begin
        JSON.parse(object)
      rescue JSON::ParserError
      end
    end

    # Decode a space delimited string of security scopes and return an array
    def decode_scopes(scopes)
      if scopes.is_a?(Array)
        scopes.map {|s| s.to_s.strip }
      else
        scopes.to_s.split(' ').map {|s| s.strip }
      end
    end

    def encode_scopes(*scopes)
      scopes = scopes.flatten.compact
      scopes.map {|s| s.to_s.strip.gsub(' ','_') }.sort.join(' ')
    end

  end
end