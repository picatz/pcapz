$LOAD_PATH.unshift File.expand_path('../../lib', __FILE__)
require 'pcapz'
require 'timeout'

cap = Pcapz.capture.new

# CTRL+C Exit
trap "SIGINT" do
  cap.stop! unless cap.stopped?
end

begin
  counter = 0
  Timeout::timeout(1) {
    cap.packets { |packet| counter += 1 }
  }
rescue
  puts "#{counter} packets per second"
  retry
ensure
  cap.stop! unless cap.stopped?
end
