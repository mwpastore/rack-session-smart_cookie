# frozen_string_literal: false
begin
  require 'rack/session/cookie'
rescue LoadError
end

module Rack
  module Session
    # Stub out a parent class so gemspec can get the version from this file.
    Cookie = Class.new unless defined?(Cookie)

    class SmartCookie < Cookie
      VERSION = '0.1.1'.freeze
    end
  end
end
