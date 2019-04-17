module Pcapz
  module Capture
    class BSD
      # https://github.com/jesnault/datalink-socket/blob/master/lib/dl_socket_bpf.rb
      BIOCGBLEN      =   0x40044266
      BIOCSBLEN      =   0xc0044266
      BIOCSETF       =   0x80084267
      BIOCFLUSH      =   0x20004268
      BIOCPROMISC    =   0x20004269
      BIOCGDLT       =   0x4004426a
      BIOCGETIF      =   0x4020426b
      BIOCSETIF      =   0x8020426c
      BIOCSRTIMEOUT  =   0x8008426d
      BIOCGRTIMEOUT  =   0x4008426e
      BIOCGSTATS     =   0x4008426f
      BIOCIMMEDIATE  =   0x80044270
      BIOCVERSION    =   0x40044271
      BIOCGRSIG      =   0x40044272
      BIOCSRSIG      =   0x80044273
      BIOCGHDRCMPLT  =   0x40044274
      BIOCSHDRCMPLT  =   0x80044275
      BIOCGSEESENT   =   0x40044276
      BIOCSSEESENT   =   0x80044277
      BIOCSDLT       =   0x80044278
      BIOCGDLTLIST   =   0xc00c4279

      attr_reader :file

      def initialize(interface = Interfacez.default, **options)
        @interface       = interface
        @buffer_size     = 0
        @file            = nil
        @internal_buffer = nil
        configure_bpf_dev
        @promiscuous = options[:promiscuous] if options.key?(:promiscuous)
      end

      def packets
        yield next_packet until @file.closed?
      end

      def next_packet
        @internal_buffer.resume
      rescue Interrupt
        exit
      rescue StandardError
        @internal_buffer = Fiber.new do
          loop do
            begin
              buffer = @file.read_nonblock(@buffer_size)
              until buffer.empty?
                Fiber.yield buffer.slice!(0, (((buffer.slice(12,4).unpack('L')[0])+18) + 3 & ~3))[18..-1] 
              end
            rescue IO::WaitReadable
              IO.select([@file])
              retry
            end
          end
        end
        retry
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
        @promiscuous = true
      end

      def promiscuous?
        @promiscuous || false
      end

      TRUTHY_PROMISC_VALUES = [true, 1].freeze
      FALESY_PROMISC_VALUES = [false, 0].freeze

      def promiscuous=(value)
        if TRUTHY_PROMISC_VALUES.include?(value)
          @promiscuous = true if @file.ioctl(BIOCPROMISC, 1).zero?
        elsif FALESY_PROMISC_VALUES.include?(value)
          @promiscuous = false if @file.ioctl(BIOCPROMISC, 0).zero?
        else
          raise "Unable to set promiscuous mode with #{value}"
        end
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
        @file.ioctl(BIOCSETIF, [interface].pack("a#{interface.size+1}"))
        @file.ioctl(BIOCIMMEDIATE, [1].pack('I'))
        @file.ioctl(BIOCGHDRCMPLT, [0].pack('N'))
        buf = [0].pack('i')
        @file.ioctl(BIOCGBLEN, buf)
        @buffer_size = buf.unpack('i')[0]
        timeout = [5, 0].pack('LL')
        @file.ioctl(BIOCSRTIMEOUT, timeout)
        @file
      rescue StandardError
        @file.close unless @file.nil? || @file.closed?
        raise "Unable to create network listener on #{@interface}!"
      end
    end
  end
end
