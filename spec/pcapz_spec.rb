RSpec.describe Pcapz do
  it "has a version number" do
    expect(Pcapz::VERSION).not_to be nil
  end
  
  it "can capture a packet" do
    cap = Pcapz.capture.new
    expect(cap.next_packet).not_to be nil
  end
  
  it "can capture a stream of packets, yielding to a block" do
    cap = Pcapz.capture.new
    cap.packets do |packet|
      expect(packet).not_to be nil
      break
    end
  end
end
