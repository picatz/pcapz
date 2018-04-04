require "interfacez"
require "pcapz/version"
require "pcapz/capture"

module Pcapz
  def self.capture
    if RUBY_PLATFORM =~ /linux/
      return Capture::Linux
    elsif  RUBY_PLATFORM =~ /darwin|freebsd|netbsd/
      return Capture::BSD
    else
      raise "This platform #{RUBY_PLATFORM} is not yet supported!"
    end
  end
end
