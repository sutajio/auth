$LOAD_PATH.unshift 'lib'
require 'auth/version'

Gem::Specification.new do |s|
  s.name        = 'auth'
  s.version     = Auth::Version
  s.summary     = 'Auth is a Redis-backed high performance OAuth2 authorization server.'
  s.description = 'A high performance OAuth2 authorization server using Sinatra and Redis, inspired by Resque. Can be run both as a standalone server or as a rack middleware.'

  s.author      = 'Niklas Holmgren'
  s.email       = 'niklas@sutajio.se'
  s.homepage    = 'http://github.com/sutajio/auth/'

  s.files         = Dir['README', 'LICENSE', 'CHANGELOG', 'Gemfile', 'Gemfile.lock', 'init.rb', 'config.ru', 'Rakefile', 'test/**/*', 'lib/**/{*,.[a-z]*}']
  s.require_path  = 'lib'

  s.files             = %w( README.md Rakefile LICENSE CHANGELOG )
  s.files            += Dir.glob("lib/**/*")
  s.files            += Dir.glob("test/**/*")
  s.files            += Dir.glob("tasks/**/*")

  s.extra_rdoc_files  = [ "LICENSE", "README.md" ]
  s.rdoc_options      = ["--charset=UTF-8"]

  s.add_dependency('rack-contrib',  '~> 1.0.0')
  s.add_dependency('sinatra',  '~> 1.0.0')
  s.add_dependency('redis',  '~> 2.0.0')
  s.add_dependency('redis-namespace',  '~> 0.8.0')

  s.add_development_dependency('rack-test',  '~> 0.5.6')
end