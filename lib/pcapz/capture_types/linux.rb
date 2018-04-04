module Pcapz
  module Capture
    class Linux
      def initialize(interface = Interfacez.default)
        @interface   = interface
        @buffer_size = 0
        @file        = nil
        configure_socket
      end

      def packets
        until @file.closed?
          yield next_packet
        end
      end
      def next_packet
        @file.recvfrom_nonblock(@buffer_size)[0]
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

      def configure_socket(interface: @interface)
        @file = Socket.new(Socket::PF_PACKET, Socket::SOCK_RAW, 0x03_00) 
        @file.setsockopt(Socket::SOL_SOCKET, Socket::SO_BINDTODEVICE, interface)
        @buffer_size = 65535
      rescue
        @file.close unless @file.nil? or @file.closed?
      end
    end  
  end
end
