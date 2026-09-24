# frozen_string_literal: true

D = Steep::Diagnostic

# The resolution logic only. The transports and the loader lean on gems without type signatures (async, async-dns,
# io-endpoint, dns-zonefile), so their signatures are declared in sig/ but their bodies are not checked.
target :lib do
  signature "sig"

  check "lib/dohyo/errors.rb"
  check "lib/dohyo/zone.rb"
  check "lib/dohyo/edns.rb"
  check "lib/dohyo/responder.rb"
  check "lib/dohyo/engine.rb"

  library "resolv"

  # resolv's bundled signatures lack HTTPS, SvcParams and the per-type constants (TypeValue, ClassValue).
  configure_code_diagnostics(D::Ruby.lenient)
end
