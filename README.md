# netconsole_log_sorter

Listens for netconsole logs on all interfaces and logs them to files based off the mac address of the incoming ethernet packet. This isn't perfect since it assumes that you're within one hop of the netconsole source, but for my usecase that's good enough.

This uses pnet to listen for _all traffic_ and then filters for UDP packets on port 6666. It is assumed any packet sent to port 6666 is a netconsole packet. We listen to all traffic instead of setting up a UDP port listener because we need to have the etherent frame to retrieve the mac address of the sender.

This requires you to have cap_net_raw or be run as root. After building I suggest chowning the executable to root and running `setcap cap_net_raw+eip` on the executable.
