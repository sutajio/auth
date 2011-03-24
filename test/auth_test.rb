require File.expand_path('test/test_helper')

class AuthTest < Test::Unit::TestCase

  def setup
    Auth.redis.flushall
  end

  def test_can_set_a_namespace_through_a_url_like_string
    assert Auth.redis
    assert_equal :auth, Auth.redis.namespace
    Auth.redis = 'localhost:9736/namespace'
    assert_equal 'namespace', Auth.redis.namespace
  end

  def test_can_register_an_account
    assert Auth.register_account('test', 'test')
  end

  def test_can_only_register_an_account_once
    assert_equal true, Auth.register_account('test', 'test')
    assert_equal false, Auth.register_account('test', 'test')
  end

  def test_can_authenticate_account
    Auth.register_account('test', 'test')
    assert_equal true, Auth.authenticate_account('test', 'test')
    assert_equal false, Auth.authenticate_account('test', 'wrong')
    assert_equal false, Auth.authenticate_account('wrong', 'wrong')
    assert_equal false, Auth.authenticate_account('wrong', 'test')
  end

  def test_can_change_password_for_an_account
    Auth.register_account('test', 'test')
    Auth.change_password('test', 'test', '123456')
    assert_equal false, Auth.authenticate_account('test', 'test')
    assert_equal true, Auth.authenticate_account('test', '123456')
  end

  def test_can_remove_account
    Auth.register_account('test', 'test')
    Auth.remove_account('test')
    assert_equal false, Auth.authenticate_account('test', 'test')
  end

  def test_can_register_a_client
    client = Auth.register_client('test-client', 'Test client', 'http://example.org/')
    assert_equal 'test-client', client.id
    assert_equal 'Test client', client.name
    assert_equal 'http://example.org/', client.redirect_uri
    assert client.secret
  end

  def test_can_authenticate_a_client
    client = Auth.register_client('test-client', 'Test client', 'http://example.org/')
    client = Auth.authenticate_client('test-client', client.secret)
    assert_equal 'test-client', client.id
    assert_equal 'Test client', client.name
    assert_equal 'http://example.org/', client.redirect_uri
    assert client.secret
    assert_equal false, Auth.authenticate_client('test-client', 'wrong')
    assert_equal false, Auth.authenticate_client('wrong', 'wrong')
    assert_equal false, Auth.authenticate_client('wrong', client.secret)
    assert_equal false, Auth.authenticate_client('wrong')
  end

  def test_can_authenticate_a_client_without_a_client_secret
    client = Auth.register_client('test-client', 'Test client', 'http://example.org/')
    client = Auth.authenticate_client('test-client')
    assert_equal 'test-client', client.id
    assert_equal 'Test client', client.name
    assert_equal 'http://example.org/', client.redirect_uri
    assert client.secret
  end

  def test_can_remove_client
    Auth.register_client('test-client', 'Test client', 'http://example.org/')
    Auth.remove_client('test-client')
    assert_equal false, Auth.authenticate_client('test-client')
  end

  def test_can_issue_a_token_for_an_account
    assert Auth.issue_token('test-account')
  end

  def test_can_validate_a_token_and_return_the_associated_account_id
    token = Auth.issue_token('test-account')
    assert_equal 'test-account', Auth.validate_token(token)
    assert_equal false, Auth.validate_token('gibberish')
  end

  def test_can_issue_a_token_for_a_specified_set_of_scopes
    assert Auth.issue_token('test-account', 'read write offline')
  end

  def test_can_validate_a_token_with_a_specified_set_of_scopes
    token = Auth.issue_token('test-account', 'read write offline')
    assert_equal 'test-account', Auth.validate_token(token)
    assert_equal 'test-account', Auth.validate_token(token, 'read')
    assert_equal 'test-account', Auth.validate_token(token, 'write offline')
    assert_equal 'test-account', Auth.validate_token(token, 'offline read write')
    assert_equal false, Auth.validate_token('gibberish', 'read')
    assert_equal false, Auth.validate_token(token, 'delete')
    assert_equal false, Auth.validate_token(token, 'read delete')
  end

  def test_can_issue_a_time_limited_token
    assert Auth.issue_token('test-account', nil, 3600)
  end

  def test_can_issue_a_refresh_token
    flunk
  end

  def test_can_redeem_a_refresh_token
    flunk
  end

  def test_can_issue_an_authorization_code
    assert Auth.issue_code('test-account', 'test-client', 'https://example.com/callback')
  end

  def test_can_validate_an_authentication_code
    code = Auth.issue_code('test-account', 'test-client', 'https://example.com/callback')
    assert_equal ['test-account', ''], Auth.validate_code(code, 'test-client', 'https://example.com/callback')
    assert_equal false, Auth.validate_code(code, 'wrong-client', 'https://example.com/callback')
    assert_equal false, Auth.validate_code(code, 'test-client', 'https://example.com/wrong-callback')
  end

  def test_can_issue_an_authorization_code_for_a_specified_set_of_scopes
    assert Auth.issue_code('test-account', 'test-client', 'https://example.com/callback', 'read write offline')
  end

  def test_can_validate_an_authentication_code_with_a_specified_set_of_scopes
    code = Auth.issue_code('test-account', 'test-client', 'https://example.com/callback', 'read write offline')
    account_id, scopes = Auth.validate_code(code, 'test-client', 'https://example.com/callback')
    assert_equal 'test-account', account_id
    assert_equal 'offline read write', scopes
  end
end