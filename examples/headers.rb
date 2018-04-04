$LOAD_PATH.unshift File.expand_path('../../lib', __FILE__)
require 'pcapz'
require 'packetgen'

cap = Pcapz.capture.new

# CTRL+C Exit
trap "SIGINT" do
  cap.stop! unless cap.stopped?
end

begin
  cap.packets do |packet|
    puts PacketGen.parse(packet).headers.map(&:method_name).join(" ")
  end
ensure
  cap.stop! unless cap.stopped?
end
