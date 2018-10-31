# PcappyBlinders

This is a dead simple script that is used to blind IP addresses in traffic captures. This is to keep hosts anonymous and avoid abuse.

## Usage

The following should help you set up and use the blinding script.

### Set up a rules file

The rules file must contain rules in the following format: `ipaddress/cidr blinding-mask`

There rules state the range of ip addresses that will be blinded, and then use a subnetting style mask to blind the addresses. Any bits that match a '0' bit in the mask will be set to '0'.

Below is an example of a local IP address that is being blinded to hide the relevant subnet.

`192.168.11.0/24 255.255.0.255`

You may add as many rules and you like.

### Run the script

`python blind-ip.py original.pcap ip.rules blind.pcap`
