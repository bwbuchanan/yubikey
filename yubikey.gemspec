# Generated by jeweler
# DO NOT EDIT THIS FILE DIRECTLY
# Instead, edit Jeweler::Tasks in Rakefile, and run 'rake gemspec'
# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name = "yubikey"
  s.version = "1.3.0"

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.authors = ["Jonathan Rudenberg", "James Cox"]
  s.date = "2012-03-25"
  s.description = "A library to verify, decode, decrypt and parse Yubikey one-time passwords."
  s.email = "jon335@gmail.com"
  s.extra_rdoc_files = [
    "LICENSE",
    "README.rdoc"
  ]
  s.files = [
    "examples/otp.rb",
    "examples/otp_verify.rb",
    "lib/yubikey.rb",
    "lib/yubikey/hex.rb",
    "lib/yubikey/modhex.rb",
    "lib/yubikey/otp.rb",
    "lib/yubikey/otp_verify.rb",
    "spec/hex_spec.rb",
    "spec/spec.opts",
    "spec/spec_helper.rb",
    "spec/yubikey_modhex_spec.rb",
    "spec/yubikey_otp_spec.rb",
    "spec/yubikey_otp_verify_spec.rb"
  ]
  s.homepage = "http://github.com/titanous/yubikey"
  s.rdoc_options = ["--title", "yubikey", "--main", "README.rdoc"]
  s.require_paths = ["lib"]
  s.rubyforge_project = "yubikey"
  s.rubygems_version = "1.8.15"
  s.summary = "A library to verify, decode, decrypt and parse Yubikey one-time passwords."

  if s.respond_to? :specification_version then
    s.specification_version = 3

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
      s.add_runtime_dependency(%q<crypt19>, [">= 0"])
      s.add_runtime_dependency(%q<ruby-hmac>, [">= 0"])
    else
      s.add_dependency(%q<crypt19>, [">= 0"])
      s.add_dependency(%q<ruby-hmac>, [">= 0"])
    end
  else
    s.add_dependency(%q<crypt19>, [">= 0"])
    s.add_dependency(%q<ruby-hmac>, [">= 0"])
  end
end

