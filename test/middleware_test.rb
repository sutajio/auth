require File.expand_path('test/test_helper')
require 'auth/middleware'

class MiddlewareTest < Test::Unit::TestCase
  include Rack::Test::Methods

  def app
    inner_app = lambda { |env| [200, {'Content-Type' => 'text/plain'}, [env['REMOTE_USER']]] }
    Auth::Middleware.new(inner_app, 'Test realm')
  end

  def setup
    Auth.redis.flushall
  end

  def test_unauthenticated_request
    env = Rack::MockRequest.env_for('/test')
    res = app.call(env)
    assert_equal 401, res[0]
    assert_equal 'Bearer realm="Test realm"', res[1]['WWW-Authenticate']
    assert_empty res[2]
  end

  def test_authenticated_request
    token = Auth.issue_token('test-user', 'read write', 3600)
    puts token
    env = Rack::MockRequest.env_for('/test',
      'HTTP_AUTHORIZATION' => "Bearer #{Base64.encode64(token)}")
    res = app.call(env)
    assert_equal 200, res[0]
    assert_equal nil, res[1]['WWW-Authenticate']
    assert_equal ['test-user'], res[2]
  end

  def test_authenticated_non_bearer_request
    env = Rack::MockRequest.env_for('/test',
      'HTTP_AUTHORIZATION' => "Basic #{Base64.encode64('test')}")
    res = app.call(env)
    assert_equal 400, res[0]
    assert_equal nil, res[1]['WWW-Authenticate']
    assert_empty res[2]
  end

  def test_authenticated_invalid_request
    env = Rack::MockRequest.env_for('/test',
      'HTTP_AUTHORIZATION' => "Bearer #{Base64.encode64('wrong')}")
    res = app.call(env)
    assert_equal 401, res[0]
    assert_equal 'Bearer realm="Test realm"', res[1]['WWW-Authenticate']
    assert_empty res[2]
  end

end