# frozen_string_literal: true
require 'rack/session/smart_cookie/version'

require 'base64'
require 'msgpack'
require 'openssl/digest'
require 'rack/session/cookie'

module Rack
  module Session
    class SmartCookie < Cookie
      BAD_DIGESTS = %w[MD2 MD4 MD5 SHA SHA1].freeze
      DEFAULT_DIGEST = 'SHA256'
      SECRET_MIN_BYTESIZE = 16

      class Base64
        if ::Base64.respond_to?(:urlsafe_encode64) && ::Base64.method(:urlsafe_encode64).arity.abs >= 2
          def self.encode(data)
            ::Base64.urlsafe_encode64(data, :padding=>false)
          end

          def self.decode(str)
            return unless str

            ::Base64.urlsafe_decode64(str)
          rescue
          end
        else
          def self.encode(data)
            ::Base64.urlsafe_encode64(data).tap { |str| str.sub!(/=*\z/, '') }
          end

          def self.decode(str)
            return unless str

            ::Base64.urlsafe_decode64(str + '=' * (-str.bytesize % 4))
          rescue
          end
        end
      end

      class MessagePack
        attr_reader :factory

        def initialize
          # Create our own factory so we don't pollute the global namespace
          # with our custom type.
          @factory = ::MessagePack::Factory.new

          # MessagePack gets custom types 0x80..0xFF
          # we get 0x60...0x80
          @factory.register_type(0x60, Symbol)
          # user gets 0x00...0x60
          yield @factory if block_given?
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
        options[:hmac] = OpenSSL::Digest(DEFAULT_DIGEST) unless options.key?(:hmac)

        super

        if @secrets.any?
          hmac = options[:hmac].new

          warn <<-MSG if BAD_DIGESTS.include?(hmac.name)
        SECURITY WARNING: You have elected to use an old and insecure message
        digest algorithm (#{hmac.class}).

        Such algorithms are generally considered to be effectively broken. It
        is strongly recommended that you elect to use a message digest algorithm
        from the SHA2 family: SHA224, SHA256, SHA384, or SHA512, or one of the
        derivatives such as SHA512/256. This will help prevent exploits that
        may be possible from crafted cookies.

        Called from: #{caller[0]}.
          MSG

          unless (SECRET_MIN_BYTESIZE..hmac.block_length).cover?(@secrets.first.bytesize)
            show_caveat = hmac.digest_length > SECRET_MIN_BYTESIZE

            message = String.new(<<-MSG)
        SECURITY WARNING: You have provided a session secret with a sub-optimal
        byte size.

        It is strongly recommended that you select a secret at least #{SECRET_MIN_BYTESIZE} bytes
        long#{'*' if show_caveat}, but not longer than the block size (#{hmac.block_length} bytes) of the selected
        message digest algorithm (#{hmac.class}). This will help
        prevent exploits that may be possible from crafted cookies.
            MSG

            message << "\n        " \
              "* - Ideally, at least #{hmac.digest_length} bytes long.\n" if show_caveat

            message << "\n        " \
              "Called from: #{caller[0]}."

            warn message
          end
        end
      end

      private

      def unpacked_cookie_data(request)
        request.fetch_header(RACK_SESSION_UNPACKED_COOKIE_DATA) do |k|
          bin_session_data = nil

          if (session_data = request.cookies[@key])
            if @secrets.any?
              if session_data =~ /\A([^.*]+)\.([^.*]+)\z/
                session_data, digest = Regexp.last_match.captures
                bin_session_data = Base64.decode(session_data)
                bin_session_data = nil unless digest_match?(bin_session_data, digest)
              end
            else
              bin_session_data = Base64.decode(session_data)
            end
          end

          request.set_header(k, coder.decode(bin_session_data) || {})
        end
      end

      def write_session(req, session_id, session, options)
        session = session.merge('session_id'=>session_id)
        bin_session_data = coder.encode(session)
        session_data = Base64.encode(bin_session_data)

        if @secrets.any?
          session_data << '.' << generate_hmac(bin_session_data, @secrets.first)
        end

        session_data
      end

      def generate_hmac(data, secret)
        Base64.encode(OpenSSL::HMAC.digest(@hmac.new, secret, data))
      end
    end
  end
end
