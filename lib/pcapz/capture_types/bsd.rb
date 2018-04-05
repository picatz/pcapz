module Pcapz
  module Capture
    class BSD
      def initialize(interface = Interfacez.default)
        @interface       = interface
        @buffer_size     = 0
        @file            = nil
        @internal_buffer = nil
        configure_bpf_dev
      end

      def packets
        until @file.closed?
          yield next_packet
        end
      end

      def next_packet
        @internal_buffer.resume
      rescue Interrupt
        exit
      rescue
        @internal_buffer = Fiber.new do
          loop do
            begin
              buffer = @file.read_nonblock(@buffer_size)
              while buffer.size > 0
                Fiber.yield buffer.slice!(0,(((buffer.slice(12,4).unpack('L')[0])+18) + 3 & ~3))[18..-1] 
              end
            rescue IO::WaitReadable
              IO.select([@file])
              retry
            end
          end
        end
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
        raise "Unable to create network listener on #{@interface}!"
      end
    end  
  end
end
