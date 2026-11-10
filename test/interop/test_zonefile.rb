# frozen_string_literal: true

require "test_helper"
require "open3"
require "interop/support/canonical_rr"

# Reads the same zone file with Dohyo::Loader and with BIND's named-checkzone, and compares the RRs line by line in
# the form of CanonicalRR. A difference is a bug in the loader's conversion or in dns-zonefile.
class TestInteropZonefile < Minitest::Test
  FIXTURE = File.expand_path("fixtures/sub.example.com.zone", __dir__)
  ORIGIN = "sub.example.com."

  def setup
    skip "named-checkzone is not installed" unless system("which named-checkzone", out: File::NULL, err: File::NULL)
  end

  def bind_lines(origin, path)
    output, status = Open3.capture2e("named-checkzone", "-D", "-o", "-", origin, path)
    assert status.success?, "named-checkzone failed:\n#{output}"
    CanonicalRR.from_bind(output)
  end

  def test_the_fixture_reads_as_bind_reads_it
    dohyo = CanonicalRR.from_zone(Dohyo::Loader.load(origin: ORIGIN, path: FIXTURE)).sort
    bind = bind_lines(ORIGIN, FIXTURE).sort

    assert_equal bind.uniq, bind, "named-checkzone printed an RR twice"
    assert_equal [], dohyo - bind, "only in dohyo"
    assert_equal [], bind - dohyo, "only in BIND"
    assert_equal 23, dohyo.size
  end
end
