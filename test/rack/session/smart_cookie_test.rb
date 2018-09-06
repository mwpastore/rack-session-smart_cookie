require_relative '../../test_helper'

require 'base64'
require 'hobby'
require 'rack/test'
require 'securerandom'

class MyApp
  include Hobby

  def session
    env['rack.session']
  end

  get '/' do
    '<div>Hello, world!</div>'
  end

  get '/set-cookie' do
    session[:foo] = 'bar'
    nil
  end

  get '/has-cookie' do
    session[:foo] == 'bar'
  end

  get '/clear-session' do
    session.clear
    session[:foo] == 'bar'
  end

  get '/destroy-session' do
    session.destroy
    session[:foo] == 'bar'
  end
end

module MyAppTest
  def app(*args, &block)
    Rack::Builder.new do
      use Rack::Session::SmartCookie, *args, &block
      run MyApp.new
    end
  end

  def capture
    stdout, stderr = StringIO.new, StringIO.new
    $stdout, $stderr = stdout, stderr
    result = yield
    $stdout, $stderr = STDOUT, STDERR
    [result, stdout.string, stderr.string]
  end

  def initialize(*)
    super

    MessagePack::DefaultFactory.register_type(0x60, Symbol)
  end
end

class DefaultBehaviorTest < Minitest::Test
  include MyAppTest
  include Rack::Test::Methods

  def app
    super :secret=>nil
  end

  def test_no_cookie_response
    capture { get '/' }

    assert last_response.ok?
    assert_equal '<div>Hello, world!</div>', last_response.body
    refute_match %r{^rack.session=}, last_response.headers['Set-Cookie']
  end

  def test_cookie_response
    *, stderr = capture { get '/set-cookie' }

    assert last_response.ok?
    assert_match %r{^rack.session=[\w-]+;}, last_response.headers['Set-Cookie']
    assert_includes stderr, 'SECURITY WARNING'
  end

  def test_no_cookie
    capture { get '/has-cookie' }
    assert last_response.ok?
    assert_equal 'false', last_response.body
  end

  def test_has_cookie
    capture { get '/set-cookie' }
    header 'Cookie', last_response.headers['Set-Cookie'][%r{^rack.session=[\w-]+}]
    capture { get '/has-cookie' }
    assert last_response.ok?
    assert_equal 'true', last_response.body
  end

  def test_cookie_injection
    session_data = Base64.urlsafe_encode64(MessagePack.pack(
      'session_id'=>'12345',
      :foo=>'bar'
    )).sub(/=*$/, '')
    header 'Cookie', "rack.session=#{session_data}"
    capture { get '/has-cookie' }
    assert last_response.ok?
    assert_equal 'true', last_response.body
  end

  def test_malformed_cookie
    session_data = Base64.urlsafe_encode64(MessagePack.pack(
      'session_id'=>12345
    )).sub(/=*$/, '')
    header 'Cookie', "rack.session=#{session_data}"
    error = assert_raises { capture { get '/has-cookie' } }
    assert_includes error.message, 'undefined method'
  end
end

class BadDigestTest < Minitest::Test
  include MyAppTest
  include Rack::Test::Methods

  def app
    super :hmac=>OpenSSL::Digest::SHA, :secret=>SecureRandom.hex(32)
  end

  def test_cookie_response
    *, stderr = capture { get '/set-cookie' }

    assert last_response.ok?
    assert_includes stderr, 'SECURITY WARNING'
  end
end

class ShortKeyTest < Minitest::Test
  include MyAppTest
  include Rack::Test::Methods

  def app
    super :secret=>'session secret'
  end

  def test_no_cookie_response
    capture { get '/' }

    assert last_response.ok?
    assert_equal '<div>Hello, world!</div>', last_response.body
    refute_match %r{^rack.session=}, last_response.headers['Set-Cookie']
  end

  def test_cookie_response
    *, stderr = capture { get '/set-cookie' }

    assert last_response.ok?
    assert_match %r{^rack.session=[\w-]+\.[\w-]+;}, last_response.headers['Set-Cookie']
    assert_includes stderr, 'SECURITY WARNING'
  end

  def test_no_cookie
    capture { get '/has-cookie' }
    assert last_response.ok?
    assert_equal 'false', last_response.body
  end

  def test_has_cookie
    capture { get '/set-cookie' }
    header 'Cookie', last_response.headers['Set-Cookie'][%r{^rack.session=[\w-]+\.[\w-]+}]
    capture { get '/has-cookie' }
    assert last_response.ok?
    assert_equal 'true', last_response.body
  end

  def test_cookie_injection
    session_data = Base64.urlsafe_encode64(MessagePack.pack(
      'session_id'=>'12345',
      :foo=>'bar'
    )).sub(/=*$/, '')
    session_data << '.' << Base64.urlsafe_encode64(SecureRandom.random_bytes(32)).sub(/=*$/, '')
    header 'Cookie', "rack.session=#{session_data}"
    capture { get '/has-cookie' }
    assert last_response.ok?
    assert_equal 'false', last_response.body
  end
end

class LongKeyTest < Minitest::Test
  include MyAppTest
  include Rack::Test::Methods

  def app
    super :secret=>SecureRandom.hex(32)
  end

  def test_no_cookie_response
    get '/'

    assert last_response.ok?
    assert_equal '<div>Hello, world!</div>', last_response.body
    refute_match %r{^rack.session=}, last_response.headers['Set-Cookie']
  end

  def test_cookie_response
    *, stderr = capture { get '/set-cookie' }

    assert last_response.ok?
    assert_match %r{^rack.session=[\w-]+\.[\w-]+;}, last_response.headers['Set-Cookie']
    refute_includes stderr, 'SECURITY WARNING'
  end
end

module DigestOptionsTest
  include MyAppTest
  include Rack::Test::Methods

  def app
    super :secret=>SecureRandom.hex(32), :digest=>@digest, :digest_bytes=>@digest_bytes
  end

  def test_cookie_response
    get '/set-cookie'

    assert last_response.ok?
    b64digest = last_response.headers['Set-Cookie'][%r{^rack.session=[\w-]+\.([\w-]+);}, 1]
    assert_equal @digest_bytes, Base64.urlsafe_decode64(b64digest).bytesize
  end
end

class FooTest < Minitest::Test
  include DigestOptionsTest

  def initialize(*)
    super

    @digest = 'SHA512'
    @digest_bytes = 64
  end
end

class BarTest < Minitest::Test
  include DigestOptionsTest

  def initialize(*)
    super

    @digest = 'SHA512'
    @digest_bytes = 32
  end
end
