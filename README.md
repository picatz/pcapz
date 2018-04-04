# Pcapz
> Pure ruby network capture API

## Installation

    $ gem install pcapz

## Usage

```ruby
require "pcapz"

# start packet capture
cap = Pcapz.capture.new

# CTRL+C Exit
trap "SIGINT" do
  cap.stop!
end

cap.packets do |packet|
  # do something with packet
  puts packet.size
end
```

## Development

Currently this is only implemented for macOS. 

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).
