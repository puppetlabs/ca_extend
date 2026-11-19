# frozen_string_literal: true

require_relative 'unit_helper'
require 'json'

# Bolt copies only the files a task's metadata lists, so a task that runs extend.sh must list
# the Ruby helper it calls, or the task fails on the target with a missing file.
RSpec.describe 'task metadata for extend.sh' do
  tasks_dir = File.expand_path('../../tasks', __dir__)
  helpers = ['ca_extend/files/ca_reissue.rb', 'ca_extend/files/extend_cert.rb']

  Dir.glob(File.join(tasks_dir, '*.json')).sort.each do |metadata|
    implementations = JSON.parse(File.read(metadata)).fetch('implementations', [])
    implementations.each do |impl|
      files = impl.fetch('files', [])
      next unless files.include?('ca_extend/files/extend.sh')

      it "#{File.basename(metadata)} (#{impl['name']}) ships the helper files" do
        expect(files).to include(*helpers)
      end
    end
  end

  it 'finds at least one task that runs extend.sh' do
    runners = Dir.glob(File.join(tasks_dir, '*.json')).select { |m| File.read(m).include?('ca_extend/files/extend.sh') }
    expect(runners).not_to be_empty
  end

  it 'has the helper files on disk' do
    helpers.each { |h| expect(File).to exist(File.expand_path("../../files/#{File.basename(h)}", __dir__)) }
  end
end
