# frozen_string_literal: true

require 'openssl'

# Loaded by the unit specs of the Ruby helpers in files/ (they need neither Puppet nor
# rspec-puppet). With COVERAGE=1, measures line coverage and fails below 90%.
if ENV['COVERAGE']
  require 'simplecov'
  SimpleCov.start do
    send(respond_to?(:skip) ? :skip : :add_filter, '/spec/')
    minimum_coverage line: 90
  end
end

# RSA key generation dominates the run time, so the keys are made once per run.
module CaExtendSpecKeys
  ROOT = OpenSSL::PKey::RSA.new(2048)
  INTERMEDIATE = OpenSSL::PKey::RSA.new(2048)
  OTHER = OpenSSL::PKey::RSA.new(2048)
end
