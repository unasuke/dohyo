# frozen_string_literal: true

require "bundler/gem_tasks"
require "minitest/test_task"

Minitest::TestTask.create

require "standard/rake"

desc "Type-check the resolution logic with Steep"
task :steep do
  sh "steep", "check"
end

task default: %i[test standard steep]
