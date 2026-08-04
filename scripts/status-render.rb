#!/usr/bin/env ruby

# Render deterministic status fragments. Phase 4 owns embedding these blocks.

require "date"
require "optparse"
require "yaml"

options = { file: "docs/status.yaml", format: "markdown" }
OptionParser.new do |parser|
  parser.banner = "Usage: ruby scripts/status-render.rb [--format markdown|html]"
  parser.on("--file PATH", "Registry to render") { |path| options[:file] = path }
  parser.on("--format FORMAT", %w[markdown html], "Output format") { |format| options[:format] = format }
end.parse!

data = YAML.safe_load(File.read(options[:file]), permitted_classes: [Date], aliases: false)
apps = Array(data["applications"])
as_of = data["as_of"]

if options[:format] == "markdown"
  puts "<!-- GENERATED: status-render.rb; do not edit inside this block -->"
  puts "Status as of #{as_of}."
  puts ""
  puts "| Application | Workflow | Disposition | Evidence |"
  puts "|---|---|---|---|"
  apps.each do |app|
    puts "| #{app["name"]} | #{app["workflow_status"]} | #{app["disposition"]} | #{app["evidence_level"]} |"
  end
  puts "<!-- END GENERATED -->"
else
  puts '<!-- GENERATED: status-render.rb; do not edit inside this block -->'
  puts '<table class="status-table">'
  puts "  <thead><tr><th>Application</th><th>Workflow</th><th>Disposition</th><th>Evidence</th></tr></thead>"
  puts "  <tbody>"
  apps.each do |app|
    cells = %w[name workflow_status disposition evidence_level].map { |key| app[key].to_s }
    puts "    <tr>#{cells.map { |cell| "<td>#{cell}</td>" }.join}</tr>"
  end
  puts "  </tbody>"
  puts "</table>"
  puts '<!-- END GENERATED -->'
end
