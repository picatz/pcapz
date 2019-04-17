module Pcapz
  module Capture
    class Linux
      # https://gist.github.com/k-sone/8036832
      ETH_P_ALL              = 0x0300 # linux/if_ether.h(network byte order)
      SIOCGIFINDEX           = 0x8933 # bits/ioctls.h
      SOL_PACKET             = 0x0107 # bits/socket.h
      PACKET_ADD_MEMBERSHIP  = 0x0001 # netpacket/packet.h
      PACKET_DROP_MEMBERSHIP = 0x0002 # netpacket/packet.h
      PACKET_MR_PROMISC      = 0x0001 # netpacket/packet.h
      IFREQ_SIZE             = 0x0028 # sizeof(ifreq) on 64bit
      IFINDEX_SIZE           = 0x0004 # sizeof(ifreq.ifr_ifindex) on 64bit
      SOCKADDR_LL_SIZE       = 0x0014 # sizeof(sockaddr_ll) on 64bit
      PACKET_MREQ_SIZE       = 0x0010 # sizeof(packet_mreq) on 64bit

      attr_reader :file

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
      rescue Interrupt
        exit
      end

      def stop!
        return nil if stopped?
        @file.close
        stopped?
      end

      def stopped?
        @file.closed?
      end

      def promiscuous!
        self.promiscuous = true
      end

      def promiscuous?
        return @promiscuous || false
      end

      def promiscuous=(value)
        mreq = Interfacez.index_of(@interface).to_s.hex.chr + "\x00\x00\x00"
        mreq << [PACKET_MR_PROMISC].pack('s')
        mreq << ("\x00" * (PACKET_MREQ_SIZE - mreq.length))
        if value == true or value == 1
          if @file.setsockopt(SOL_PACKET, PACKET_ADD_MEMBERSHIP, mreq) == 0
            @promiscuous = true
          end
          return true if promiscuous? 
        elsif value == false or value == 0
          if @file.setsockopt(SOL_PACKET, PACKET_DROP_MEMBERSHIP, mreq) == 0
            @promiscuous = false
          end
          return true unless promiscuous? 
        else
          raise "Unable to set promiscuous mode with #{value}"
        end
      end

      private

      def configure_socket(interface: @interface)
        @file = Socket.new(Socket::PF_PACKET, Socket::SOCK_RAW, 0x03_00) 
        @file.setsockopt(Socket::SOL_SOCKET, Socket::SO_BINDTODEVICE, interface)
        @file.setsockopt(Socket::SOL_SOCKET, Socket::SO_REUSEADDR, true)
        @buffer_size = 65535
      rescue
        @file.close unless @file.nil? or @file.closed?
        raise "Unable to create network listener on #{@interface}!"
      end
    end  
  end
end
