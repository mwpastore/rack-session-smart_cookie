# frozen_string_literal: false
require 'rack/session/cookie'

module Rack
  module Session
    class SmartCookie < Cookie
      VERSION = '0.1.0'.freeze
    end
  end
end
