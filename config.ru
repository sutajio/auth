#!/usr/bin/env ruby

$LOAD_PATH.unshift ::File.expand_path(::File.dirname(__FILE__) + '/lib')
require 'auth/server'

if ENV['REDISTOGO_URL'] || ENV['REDIS_URL']
  Auth.redis = ENV['REDISTOGO_URL'] || ENV['REDIS_URL']
end

use Rack::ShowExceptions
run Auth::Server.new
