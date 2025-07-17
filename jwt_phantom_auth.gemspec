# frozen_string_literal: true

require_relative "lib/jwt_phantom_auth/version"

Gem::Specification.new do |spec|
  spec.name = "jwt_phantom_auth"
  spec.version = JwtPhantomAuth::VERSION
  spec.authors = ["rahul", "arun"]
  spec.email = ["rahul9.98.be@gmail.com"]

  spec.summary = "JWT-based authentication gem using phantom token technique for secure API authentication"
  spec.description = "A comprehensive JWT authentication gem that implements the phantom token technique, providing secure API authentication with short-lived access tokens and long-lived refresh tokens."
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.1.0"

  spec.metadata["allowed_push_host"] = "https://rubygems.org"

  spec.metadata["homepage_uri"] = spec.homepage

  # Specify which files should be added to the gem when it is released.
  # The `git ls-files -z` loads the files in the RubyGem that have been added into git.
  gemspec = File.basename(__FILE__)
  spec.files = IO.popen(%w[git ls-files -z], chdir: __dir__, err: IO::NULL) do |ls|
    ls.readlines("\x0", chomp: true).reject do |f|
      (f == gemspec) ||
        f.start_with?(*%w[bin/ test/ spec/ features/ .git .github appveyor Gemfile])
    end
  end
  spec.bindir = "exe"
  spec.executables = spec.files.grep(%r{\Aexe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  # Core dependencies
  spec.add_dependency "jwt", "~> 2.7"
  spec.add_dependency "bcrypt", "~> 3.1"
  spec.add_dependency "redis", "~> 5.0"
  
  # Development dependencies
  spec.add_development_dependency "rspec", "~> 3.12"
  spec.add_development_dependency "rake", "~> 13.0"
  spec.add_development_dependency "rubocop", "~> 1.50"

  # For more information and examples about making a new gem, check out our
  # guide at: https://bundler.io/guides/creating_gem.html
end
