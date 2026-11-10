# frozen_string_literal: true

require "bundler/gem_tasks"
require "minitest/test_task"

# test/interop/ needs tools from outside the bundle (BIND, Knot DNS, docker and others); `rake interop` runs it.
Minitest::TestTask.create do |t|
  t.test_globs = ["test/test_*.rb", "test/integration/**/test_*.rb"]
end

namespace :interop do
  Minitest::TestTask.create(:differential) do |t|
    t.test_globs = ["test/interop/test_differential.rb"]
  end

  Minitest::TestTask.create(:compliance) do |t|
    t.test_globs = ["test/interop/test_compliance.rb"]
  end

  Minitest::TestTask.create(:zonefile) do |t|
    t.test_globs = ["test/interop/test_zonefile.rb"]
  end
end

desc "Check dohyo against other implementations and tools (skips what is not installed)"
task interop: %w[interop:differential interop:compliance interop:zonefile]

require "standard/rake"

desc "Type-check the resolution logic with Steep"
task :steep do
  sh "steep", "check"
end

task default: %i[test standard steep]
