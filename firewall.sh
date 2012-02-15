#!/bin/sh
#------------------------------------------------------------------------------
#
# Firewall script
# Compiler: Cal Harding <cal@calharding.net>
#                       <cal@dcdata.co.za>
# License ISC License
# URL: http://www.calharding.net
# Sources: IRC, man pages, HOWTOs, Linux iptables Reference by Greg Purdy
#
# Copyright (c) 2011, Cal Harding <cal@calharding.net>
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#
#------------------------------------------------------------------------------

IPT=/sbin/iptables
EIF="eth0"
EIP="203.0.113.77"
VIF="tun0"

# Logging options
LOG="LOG --log-level info --log-tcp-sequence"
LOG="$LOG --log-tcp-options --log-ip-options"

# Rate limiting
RLIMIT="-m limit --limit 3/s --limit-burst 8"

#/sbin/modprobe ip_nat_ftp
#/sbin/modprobe ip_conntrack_ftp

# Cleanup
#-----------------------------------------------------------------------------

# Flush firewall
$IPT -F
$IPT -t nat -F
$IPT -t mangle -F

# Delete all non-default chains
$IPT -X
$IPT -t nat -X
$IPT -t mangle -X

# zero out packet counters
$IPT -Z
$IPT -t nat -Z
$IPT -t mangle -Z

# Set up default policies
#----------------------------------------------------------------------------

$IPT -P INPUT ACCEPT
$IPT -P FORWARD ACCEPT
$IPT -P OUTPUT ACCEPT

# Log and accept
$IPT -N AC_LOG
$IPT -A AC_LOG -j $LOG $RLIMIT --log-prefix "ACCEPT: "
$IPT -A AC_LOG -j ACCEPT

# Log and drop
$IPT -N DR_LOG
$IPT -A DR_LOG -j $LOG $RLIMIT --log-prefix "DROP: "
$IPT -A DR_LOG -j DROP

# Log and reject (TCP packets are rejected with a TCP reset)
$IPT -N RE_LOG
$IPT -A RE_LOG -j $LOG $RLIMIT --log-prefix "REJECT: "
$IPT -A RE_LOG -p tcp -j REJECT --reject-with tcp-reset
$IPT -A RE_LOG -j REJECT

# Kernel configuration.
#------------------------------------------------------------------------------

# Disable IP forwarding.
# On => Off = (reset)
#echo 1 > /proc/sys/net/ipv4/ip_forward
#echo 0 > /proc/sys/net/ipv4/ip_forward

# Enable IP spoofing protection
for i in /proc/sys/net/ipv4/conf/*/rp_filter; do echo 1 > $i; done

# Protect against SYN flood attacks
echo 1 > /proc/sys/net/ipv4/tcp_syncookies

# Ignore all incoming ICMP echo requests
echo 0 > /proc/sys/net/ipv4/icmp_echo_ignore_all

# Ignore ICMP echo requests to broadcast
echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts

# Log packets with impossible addresses.
for i in /proc/sys/net/ipv4/conf/*/log_martians; do echo 1 > $i; done

# Don't log invalid responses to broadcast
echo 1 > /proc/sys/net/ipv4/icmp_ignore_bogus_error_responses

# Don't accept or send ICMP redirects.
for i in /proc/sys/net/ipv4/conf/*/accept_redirects; do echo 0 > $i; done
for i in /proc/sys/net/ipv4/conf/*/send_redirects; do echo 0 > $i; done

# Don't accept source routed packets.
for i in /proc/sys/net/ipv4/conf/*/accept_source_route; do echo 0 > $i; done

# Disable multicast routing
#for i in /proc/sys/net/ipv4/conf/*/mc_forwarding; do echo 0 > $i; done

# Disable proxy_arp.
for i in /proc/sys/net/ipv4/conf/*/proxy_arp; do echo 0 > $i; done

# Enable secure redirects, i.e. only accept ICMP redirects for gateways
# Helps against MITM attacks.
for i in /proc/sys/net/ipv4/conf/*/secure_redirects; do echo 1 > $i; done

# Disable bootp_relay
for i in /proc/sys/net/ipv4/conf/*/bootp_relay; do echo 0 > $i; done

# Allow loopback to do anything.
#------------------------------------------------------------------------------

$IPT -A INPUT -i lo -j ACCEPT
$IPT -A OUTPUT -o lo -j ACCEPT

# Syn flood protection
#------------------------------------------------------------------------------

$IPT -N SYN_FLOOD
$IPT -A INPUT -p tcp --syn -j SYN_FLOOD
$IPT -A SYN_FLOOD $RLIMIT -j RETURN
$IPT -A SYN_FLOOD -j DROP

# Test for invalid TCP flags (portscanning)
# -----------------------------------------------------------------------------

$IPT -N BAD_FLAGS
$IPT -A BAD_FLAGS -j LOG --log-level debug --log-prefix "IPT BAD_FLAGS: "
$IPT -A BAD_FLAGS -j DROP

$IPT -N TCP_FLAGS
$IPT -A TCP_FLAGS -p tcp --tcp-flags ACK,FIN FIN -j BAD_FLAGS
$IPT -A TCP_FLAGS -p tcp --tcp-flags ACK,PSH PSH -j BAD_FLAGS
$IPT -A TCP_FLAGS -p tcp --tcp-flags ACK,URG URG -j BAD_FLAGS
$IPT -A TCP_FLAGS -p tcp --tcp-flags FIN,RST FIN,RST -j BAD_FLAGS
$IPT -A TCP_FLAGS -p tcp --tcp-flags SYN,FIN SYN,FIN -j BAD_FLAGS
$IPT -A TCP_FLAGS -p tcp --tcp-flags SYN,RST SYN,RST -j BAD_FLAGS
$IPT -A TCP_FLAGS -p tcp --tcp-flags ALL ALL -j BAD_FLAGS
$IPT -A TCP_FLAGS -p tcp --tcp-flags ALL NONE -j BAD_FLAGS
$IPT -A TCP_FLAGS -p tcp --tcp-flags ALL FIN,PSH,URG -j BAD_FLAGS
$IPT -A TCP_FLAGS -p tcp --tcp-flags ALL SYN,FIN,PSH,URG -j BAD_FLAGS
$IPT -A TCP_FLAGS -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j BAD_FLAGS

#########################
# FORWARDING
#########################

# for openvpn
$IPT -A FORWARD -p tcp -i $VIF -s 10.17.165.0/24 -j ACCEPT

$IPT -A FORWARD -o $VIF -d 10.17.165.0/24 -m state --state ESTABLISHED,RELATED -j ACCEPT
$IPT -A FORWARD -j RE_LOG

##########################
# INPUT
##########################

# Drop any traffic from IANA-reserved IPs.
#------------------------------------------------------------------------------

$IPT -A INPUT -s 0.0.0.0/7 -j DR_LOG
#$IPT -A INPUT -s 2.0.0.0/8 -j DR_LOG
#$IPT -A INPUT -s 5.0.0.0/8 -j DR_LOG
#$IPT -A INPUT -s 7.0.0.0/8 -j DR_LOG
$IPT -A INPUT -s 10.0.0.0/8 -j DR_LOG
#$IPT -A INPUT -s 23.0.0.0/8 -j DR_LOG
#$IPT -A INPUT -s 27.0.0.0/8 -j DR_LOG
#$IPT -A INPUT -s 31.0.0.0/8 -j DR_LOG
#$IPT -A INPUT -s 36.0.0.0/7 -j DR_LOG
#$IPT -A INPUT -s 39.0.0.0/8 -j DR_LOG
#$IPT -A INPUT -s 42.0.0.0/8 -j DR_LOG
#$IPT -A INPUT -s 49.0.0.0/8 -j DR_LOG
#$IPT -A INPUT -s 50.0.0.0/8 -j DR_LOG
#$IPT -A INPUT -s 77.0.0.0/8 -j DR_LOG
#$IPT -A INPUT -s 78.0.0.0/7 -j DR_LOG
#$IPT -A INPUT -s 92.0.0.0/6 -j DR_LOG
#$IPT -A INPUT -s 96.0.0.0/4 -j DR_LOG # blocks ssh for some reason
#$IPT -A INPUT -s 112.0.0.0/5 -j DR_LOG
#$IPT -A INPUT -s 120.0.0.0/8 -j DR_LOG
$IPT -A INPUT -s 169.254.0.0/16 -j DR_LOG
$IPT -A INPUT -s 172.16.0.0/12 -j DR_LOG
#$IPT -A INPUT -s 173.0.0.0/8 -j DR_LOG
#$IPT -A INPUT -s 174.0.0.0/7 -j DR_LOG
#$IPT -A INPUT -s 176.0.0.0/5 -j DR_LOG
#$IPT -A INPUT -s 184.0.0.0/6 -j DR_LOG
$IPT -A INPUT -s 192.0.2.0/24 -j DR_LOG
$IPT -A INPUT -s 192.88.99.0/24 -j DR_LOG
#$IPT -A INPUT -s 197.0.0.0/8 -j DR_LOG
$IPT -A INPUT -s 198.18.0.0/15 -j DR_LOG
$IPT -A INPUT -s 198.51.100.0/24 -j DR_LOG
$IPT -A INPUT -s 203.0.113.0/24 -j DR_LOG
#$IPT -A INPUT -s 223.0.0.0/8 -j DR_LOG
$IPT -A INPUT -s 224.0.0.0/4 -j DR_LOG
$IPT -A INPUT -s 240.0.0.0/4 -j DR_LOG

# Drop all fragmented ICMP packets (usually malicious)
$IPT -A INPUT -p icmp --fragment -j DR_LOG
$IPT -A OUTPUT -p icmp --fragment -j DR_LOG
$IPT -A FORWARD -p icmp --fragment -j DR_LOG

# Make it hard to multi-ping
$IPT -A INPUT -p icmp -m limit --limit 1/s --limit-burst 2 -j ACCEPT
$IPT -A INPUT -p icmp -m limit --limit 1/s --limit-burst 2 -j LOG --log-prefix "PING-DROP: "
$IPT -A INPUT -p icmp -j DROP

#OpenVPN
$IPT -A INPUT -i $EIF -p tcp --dport 11194 -j ACCEPT

# SSH
# if > 4 packets in 60 seconds from the same ip addr, drop subsequent
$IPT -A INPUT -i $EIF -p tcp --dport 22 -m state --state NEW -m recent --set
$IPT -A INPUT -i $EIF -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 60 --hitcount 4 -j DR_LOG

$IPT -A INPUT -i $EIF -p tcp --dport 22 -j ACCEPT

# Drop invalid packets
$IPT -A INPUT -m state --state INVALID -j DROP
$IPT -A OUTPUT -m state --state INVALID -j DROP

$IPT -A INPUT -i $EIF -m state --state ESTABLISHED,RELATED -j ACCEPT
$IPT -A INPUT -j RE_LOG
