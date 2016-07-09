#!/bin/sh
iptables -F
iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/m -j ACCEPT