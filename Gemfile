# frozen_string_literal: true

source "https://rubygems.org"

# Specify your gem's dependencies in dohyo.gemspec
gemspec

# DNS over QUIC. Not in the gemspec: it comes from a fork with the bindings dohyo needs, which RubyGems cannot
# depend on.
gem "protocol-quic", git: "https://github.com/unasuke/socketry-protocol-quic.git", branch: "ruby-stream-io-bindings"

gem "irb"
gem "rake", ">= 13.0"

gem "minitest"

gem "standard"
