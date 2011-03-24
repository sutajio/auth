require 'base64'
require 'digest/sha2'

module Auth
  module Helpers

    # Generate a unique cryptographically secure secret
    def generate_secret
      Base64.encode64(
        Digest::SHA256.digest("#{Time.now}-#{rand}")
      ).gsub('/','x').gsub('+','y').gsub('=','').strip
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