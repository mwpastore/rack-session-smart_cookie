# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'rack/session/smart_cookie/version'

Gem::Specification.new do |spec|
  spec.name          = 'rack-session-smart_cookie'
  spec.version       = Rack::Session::SmartCookie::VERSION
  spec.authors       = ['Mike Pastore']
  spec.email         = ['mike@oobak.org']

  spec.summary       = %q{Slighty smarter session cookies for Rack apps}
  spec.homepage      = 'https://github.com/mwpastore/rack-session-smart_cookie#readme'
  spec.license       = 'MIT'

  spec.files         = %x{git ls-files -z}.split("\x0").reject do |f|
    f.match(%r{^(test|spec|features)/})
  end
  spec.bindir        = 'exe'
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = %w[lib]

  spec.required_ruby_version = '>= 2.2.8'

  spec.add_dependency 'msgpack', '~> 1.1'
  spec.add_dependency 'rack', ENV.fetch('RACK_VERSION', '~> 2.0.0')

  spec.add_development_dependency 'bundler', '~> 1.15'
  spec.add_development_dependency 'hobby', '~> 0.1.0'
  spec.add_development_dependency 'minitest', '~> 5.0'
  spec.add_development_dependency 'rack-test', '~> 0.7.0'
  spec.add_development_dependency 'rake', '~> 12.0'
end
