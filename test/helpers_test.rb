require File.expand_path('test/test_helper')

class HelpersTest < Test::Unit::TestCase

  def test_urlsafe_base64
    message = Auth.urlsafe_base64_encode('test')
    assert_equal 'test', Auth.urlsafe_base64_decode(message)
  end

end
