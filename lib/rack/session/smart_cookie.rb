# frozen_string_literal: true
require 'base64'
require 'msgpack'
require 'openssl'

module Rack
  module Session
    class SmartCookie
      BAD_DIGESTS = %w[
        OpenSSL::Digest::MD2
        OpenSSL::Digest::MD4
        OpenSSL::Digest::MD5
        OpenSSL::Digest::SHA
        OpenSSL::Digest::SHA1
      ].freeze
      DEFAULT_DIGEST = OpenSSL::Digest::SHA256
      DELIMITER = '.'

      class Base64
        def self.encode(data)
          ::Base64.urlsafe_encode64(data, :padding=>false)
        end

        def self.decode(bin)
          return unless bin

          ::Base64.urlsafe_decode64(bin)
        rescue
        end
      end

      class MessagePack
        attr_reader :factory

        def initialize
          # Create our own factory so we don't pollute the global namespace
          # with our custom type.
          @factory = ::MessagePack::Factory.new
          # user gets 0x00..0x60
          # we get 0x60..0x80
          # MessagePack gets 0x80...0xFF
          @factory.register_type(0x60, Symbol)
        end

        def encode(data)
          # https://github.com/msgpack/msgpack-ruby/issues/141
          factory.packer.write(data).to_str
        end

        def decode(bin)
          return unless bin

          # https://github.com/msgpack/msgpack-ruby/issues/141
          factory.unpacker.feed(bin).read
        rescue
        end
      end

      def initialize(app, options={})
        options[:coder] ||= MessagePack.new
        options[:hmac] = DEFAULT_DIGEST unless options.key?(:hmac)

        super

        warn <<-MSG if @secrets.any? && BAD_DIGESTS.include?(options[:hmac].name)
        SECURITY WARNING: You have elected to use an old and insecure message
        digest algorithm (#{options[:hmac].name}).

        Such algorithms are generally considered to be effectively broken. It
        is strongly recommended that you elect to use a message digest algorithm
        from the SHA2 family: SHA224, SHA256, SHA384, or SHA512, or one of the
        derivatives such as SHA512/256. This will help prevent exploits that
        may be possible from crafted cookies.

        Called from: #{caller[0]}.
        MSG
      end

      private

      def unpacked_cookie_data(request)
        request.fetch_header(RACK_SESSION_UNPACKED_COOKIE_DATA) do |k|
          session_data = request.cookies[@key]

          if @secrets.any? && session_data
            digest, session_data = session_data.reverse.split(DELIMITER, 2)
            digest.reverse! if digest
            session_data = session_data.reverse! if session_data
            bin_session_data = Base64.decode(session_data) if session_data
            bin_session_data = nil unless digest_match?(bin_session_data, digest)
          else
            bin_session_data = nil
          end

          request.set_header(k, coder.decode(bin_session_data) || {})
        end
      end

      def write_session(req, session_id, session, options)
        session = session.merge('session_id'=>session_id)
        bin_session_data = coder.encode(session)
        session_data = Base64.encode(bin_session_data)

        if @secrets.any?
          session_data << DELIMITER << generate_hmac(bin_session_data, @secrets.first)
        end

        session_data
      end

      def generate_hmac(data, secret)
        Base64.encode(OpenSSL::HMAC.digest(@hmac.new, secret, data))
      end

      def delete_session(req, session_id, options)
        delete_cookie(@key, :domain=>options[:domain], :path=>options[:path])

        nil
      end
    end
  end
end
