require 'rubygems'
require 'sinatra/base'
require 'erb'
require 'cgi'
require 'uri'
require 'auth'

module Auth
  class Server < Sinatra::Base
    dir = File.dirname(File.expand_path(__FILE__))

    set :views,  "#{dir}/server/views"
    set :public, "#{dir}/server/public"
    set :static, true
    set :raise_errors, true
    set :show_exceptions, true if development?

    helpers do
      include Rack::Utils
      alias_method :h, :escape_html

      def cgi_escape(text)
        URI.escape(CGI.escape(text.to_s), '.').gsub(' ','+')
      end

      def query_string(parameters, escape = true)
        if escape
          parameters.map{|key,val| val ? "#{cgi_escape(key)}=#{cgi_escape(val)}" : nil }.compact.join('&')
        else
          parameters.map{|key,val| val ? "#{key}=#{val}" : nil }.compact.join('&')
        end
      end

      def merge_uri_with_query_parameters(uri, parameters = {})
        parameters = query_string(parameters)
        if uri.to_s =~ /\?/
          parameters = "&#{parameters}"
        else
          parameters = "?#{parameters}"
        end
        URI.escape(uri.to_s) + parameters.to_s
      end

      def merge_uri_with_fragment_parameters(uri, parameters = {})
        parameters = query_string(parameters)
        parameters = "##{parameters}"
        URI.escape(uri.to_s) + parameters.to_s
      end

      def merge_uri_based_on_response_type(uri, parameters = {})
        case params[:response_type]
        when 'code', nil
          merge_uri_with_query_parameters(uri, parameters)
        when 'token', 'code_and_token'
          merge_uri_with_fragment_parameters(uri, parameters)
        end
      end

      def sentry
        if Auth.sentry
          @sentry ||= Auth.sentry.new(request)
        else
          @sentry ||= request.env['warden'] || request.env['rack.auth'] || Sentry.new(request)
        end
      end

      def validate_redirect_uri!
        params[:redirect_uri] ||= sentry.user(:client).redirect_uri
        if URI(params[:redirect_uri]).host.to_s.downcase != URI(sentry.user(:client).redirect_uri).host.to_s.downcase
          halt(400, 'Invalid redirect URI')
        end
      rescue URI::InvalidURIError
        halt(400, 'Invalid redirect URI')
      end
    end

    error AuthException do
      headers['Content-Type'] = 'application/json;charset=utf-8'
      [400, {
          :error => {
            :type => 'OAuthException',
            :message => request.env['sinatra.error'].message
          }
        }.to_json]
    end

    error UnsupportedResponseType do
      redirect_uri = merge_uri_based_on_response_type(
        params[:redirect_uri],
        :error => 'unsupported_response_type',
        :error_description => request.env['sinatra.error'].message,
        :state => params[:state])
      redirect redirect_uri
    end

    before do
      headers['Cache-Control'] = 'no-store'
    end

    ['', '/authorize'].each do |action|
      get action do
        sentry.authenticate!(:client)
        validate_redirect_uri!
        sentry.authenticate!
        unless ['code', 'token', 'code_and_token', nil].include?(params[:response_type])
          raise UnsupportedResponseType,
            'The authorization server does not support obtaining an ' +
            'authorization code using this method.'
        end
        @client = sentry.user(:client)
        erb(:authorize)
      end
    end

    ['', '/authorize'].each do |action|
      post action do
        sentry.authenticate!(:client)
        validate_redirect_uri!
        sentry.authenticate!
        case params[:response_type]
        when 'code', nil
          authorization_code = Auth.issue_code(sentry.user.id,
                                               sentry.user(:client).id,
                                               params[:redirect_uri],
                                               params[:scope])
          redirect_uri = merge_uri_with_query_parameters(
            params[:redirect_uri],
            :code => authorization_code,
            :state => params[:state])
          redirect redirect_uri
        when 'token'
          ttl = ENV['AUTH_TOKEN_TTL'].to_i
          access_token = Auth.issue_token(sentry.user.id, params[:scope], ttl)
          redirect_uri = merge_uri_with_fragment_parameters(
            params[:redirect_uri],
            :access_token => access_token,
            :token_type => 'bearer',
            :expires_in => ttl,
            :expires => ttl, # Facebook compatibility
            :scope => params[:scope],
            :state => params[:state])
          redirect redirect_uri
        when 'code_and_token'
          ttl = ENV['AUTH_TOKEN_TTL'].to_i
          authorization_code = Auth.issue_code(sentry.user.id,
                                               sentry.user(:client).id,
                                               params[:redirect_uri],
                                               params[:scope])
          access_token = Auth.issue_token(sentry.user.id, params[:scope], ttl)
          redirect_uri = merge_uri_with_fragment_parameters(
            params[:redirect_uri],
            :code => authorization_code,
            :access_token => access_token,
            :token_type => 'bearer',
            :expires_in => ttl,
            :expires => ttl, # Facebook compatibility
            :scope => params[:scope],
            :state => params[:state])
          redirect redirect_uri
        else
          raise UnsupportedResponseType,
            'The authorization server does not support obtaining an ' +
            'authorization code using this method.'
        end
      end
    end

    ['/token', '/access_token'].each do |action|
      post action do
        sentry.authenticate!(:client)
        validate_redirect_uri!
        case params[:grant_type]
        when 'authorization_code', nil
          account_id, scopes = Auth.validate_code(
            params[:code], sentry.user(:client).id, params[:redirect_uri])
          if account_id
            ttl = ENV['AUTH_TOKEN_TTL'].to_i
            access_token = Auth.issue_token(account_id, scopes, ttl)
            @token = {
              :access_token => access_token,
              :token_type => 'bearer',
              :expires_in => ttl,
              :expires => ttl, # Facebook compatibility
              :scope => scopes
            }
          else
            raise AuthException, 'Invalid authorization code'
          end
        when 'password'
          sentry.authenticate!
          ttl = ENV['AUTH_TOKEN_TTL'].to_i
          access_token = Auth.issue_token(sentry.user.id, params[:scope], ttl)
          @token = {
            :access_token => access_token,
            :token_type => 'bearer',
            :expires_in => ttl,
            :expires => ttl, # Facebook compatibility
            :scope => params[:scope]
          }
        when 'refresh_token'
          raise AuthException, 'Unsupported grant type'
        when 'client_credentials'
          access_token = Auth.issue_token("client:#{sentry.user(:client).id}")
          @token = {
            :access_token => access_token,
            :token_type => 'client'
          }
        else
          raise AuthException, 'Unsupported grant type'
        end
        if request.accept.include?('application/json')
          headers['Content-Type'] = 'application/json;charset=utf-8'
          [200, @token.to_json]
        else
          headers['Content-Type'] = 'application/x-www-form-urlencoded;charset=utf-8'
          [200, query_string(@token)]
        end
      end
    end

    get '/validate' do
      sentry.authenticate!(:client)
      headers['Content-Type'] = 'text/plain;charset=utf-8'
      if account_id = Auth.validate_token(params[:access_token], params[:scope])
        [200, account_id]
      else
        [403, 'Forbidden']
      end
    end
  end
end