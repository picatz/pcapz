$LOAD_PATH.unshift File.expand_path('../../lib', __FILE__)
require 'pcapz'
require 'pry'

cap = Pcapz.capture.new

# CTRL+C Exit
trap "SIGINT" do
  cap.stop! unless cap.stopped?
  exit
end

begin
  binding.pry
ensure
  cap.stop! unless cap.stopped?
end
