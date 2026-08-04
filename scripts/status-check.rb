#!/usr/bin/env ruby

# Validate the canonical current-status registry.

require "date"
require "optparse"
require "yaml"

options = { file: "docs/status.yaml" }
OptionParser.new do |parser|
  parser.banner = "Usage: ruby scripts/status-check.rb [--file PATH]"
  parser.on("--file PATH", "Registry to validate") { |path| options[:file] = path }
end.parse!

errors = []
path = options[:file]

begin
  data = YAML.safe_load(File.read(path), permitted_classes: [Date], aliases: false)
rescue StandardError => e
  abort "status-check: cannot parse #{path}: #{e.message}"
end

required = %w[schema_version as_of coverage status_vocabulary applications capabilities preservation milestones]
required.each { |key| errors << "missing top-level key: #{key}" unless data.key?(key) }

unless data["schema_version"] == 1
  errors << "schema_version must be 1"
end

workflow_values = Array(data.dig("status_vocabulary", "workflow"))
disposition_values = Array(data.dig("status_vocabulary", "disposition"))
evidence_values = Array(data.dig("status_vocabulary", "evidence"))

unless data["as_of"].is_a?(Date)
  errors << "as_of must be an ISO date"
end

coverage = data["coverage"] || {}
%w[registered_exports milestone_qualified_implementations unweighted_percent weighted_percent metric_definition verified].each do |key|
  errors << "coverage missing #{key}" if coverage[key].nil?
end

if coverage["verified"] && !coverage["verified"].is_a?(Date)
  errors << "coverage.verified must be an ISO date"
end

path_exists = lambda do |candidate|
  candidate.is_a?(String) && File.file?(candidate)
end

validate_record = lambda do |record, label|
  unless record.is_a?(Hash)
    errors << "#{label} must be a mapping"
    next
  end

  errors << "#{label} missing workflow_status" unless workflow_values.include?(record["workflow_status"])
  errors << "#{label} has invalid disposition" unless disposition_values.include?(record["disposition"])
  errors << "#{label} has invalid evidence_level" unless evidence_values.include?(record["evidence_level"])
  errors << "#{label} missing verified date" unless record["verified"].is_a?(Date)

  evidence = record["evidence"]
  if !evidence.is_a?(Array) || evidence.empty?
    errors << "#{label} must have evidence links"
  else
    evidence.each do |evidence_path|
      errors << "#{label} evidence missing: #{evidence_path}" unless path_exists.call(evidence_path)
    end
  end
end

Array(data["applications"]).each_with_index { |record, index| validate_record.call(record, "applications[#{index}]") }
Array(data["capabilities"]).each_with_index { |record, index| validate_record.call(record, "capabilities[#{index}]") }
Array(data["preservation"]).each_with_index { |record, index| validate_record.call(record, "preservation[#{index}]") }

Array(data["milestones"]).each_with_index do |record, index|
  validate_record.call(record.merge("workflow_status" => "validated"), "milestones[#{index}]")
end

if errors.empty?
  puts "status-check: OK (#{Array(data["applications"]).length} applications, #{Array(data["capabilities"]).length} capabilities, #{Array(data["preservation"]).length} preservation targets, #{Array(data["milestones"]).length} milestones)"
  exit 0
end

warn "status-check: FAILED"
errors.each { |error| warn "- #{error}" }
exit 1
