module Pcapz
  class Capture
    def initialize(interface = Interfacez.default)
      @interface   = interface
      @buffer_size = 0
      @file        = nil
      configure_bpf_dev
    end

    def packets
      return nil if @file.closed?
      if block_given?
        loop do
          buffer = @file.read_nonblock(@buffer_size)
          while buffer.size > 0
            size, hdrlen = header_decode(buffer)
            pkt = buffer.slice!(0,size)[hdrlen..-1] 
            yield pkt unless pkt.nil?
          end
        end
      else
        packets = []
        buffer = @file.read_nonblock(@buffer_size)
        while buffer.size > 0
          size, hdrlen = header_decode(buffer)
          pkt = buffer.slice!(0,size)[hdrlen..-1] 
          packets << pkt unless pkt.nil?
        end
        return packets
      end
      return true
    rescue EOFError, Errno::EAGAIN
      retry
    rescue IO::WaitReadable
      IO.select([@file])
      retry
    end

    def file
      @file
    end

    def stop!
      return nil if stopped?
      @file.close
      stopped?
    end

    def stopped?
      @file.closed?
    end

    private

    def configure_bpf_dev(interface: @interface)
      Dir.glob('/dev/bpf*') do |item|
        begin
          @file = File.open(item)   
        rescue Errno::EBUSY
          next
        end
      end
      raise "Unable to start a packet capture on any device" if @file.nil?
      @file.ioctl(0x8020426c, [interface].pack("a#{interface.size+1}"))
      @file.ioctl(0x80044270, [1].pack('I'))
      @file.ioctl(0x40044274, [0].pack('N'))
      buf = [0].pack('i')
      @file.ioctl(0x40044266, buf)
      @buffer_size = buf.unpack('i')[0]
      timeout = [5,0].pack('LL')
      @file.ioctl(0x8008426d, timeout)
      return @file 
    rescue
      @file.close unless @file.nil? or @file.closed?
    end

    def packet_size(n)
      n+3 & ~3
    end

    def header_decode(hdr)
      datalen = hdr.slice(12,4).unpack('L')[0]
      hdrlen  = hdr.slice(16,2).unpack('v')[0]
      size    = packet_size(datalen+hdrlen)
      [size, hdrlen]
    end
  end  
end
