# ptp_message_count

## Description

A command-line tool, written in Go, to monitor and summarise PTP traffic
on an IP network. It counts messages received over a given time period,
for both PTPv1 and PTPv2, displaying a summary of each message type and
the source addresses sending them.

## Example

```
# go run ./ptp_message_count.go -I eno1 -c 1 -s
Monitoring PTP messages on network interface eno1
Reporting summary statistics every 5s
Subscribed to multicast groups 224.0.0.107, 224.0.1.129, 224.0.1.130, 224.0.1.131, 224.0.1.132 on ports 319, 320
Press Ctrl+C to stop

PTP messages:   40,    8.00 msgs/sec
 v1 messages:    0,    0.00 msgs/sec
 v2 messages:   40,    8.00 msgs/sec
Message type:
  Type  0 : Sync       :     5 messages,   1.00 msgs/sec
  Type  1 : Delay_Req  :    14 messages,   2.80 msgs/sec
  Type  8 : Follow_Up  :     5 messages,   1.00 msgs/sec
  Type  9 : Delay_Resp :    13 messages,   2.60 msgs/sec
  Type 11 : Announce   :     3 messages,   0.60 msgs/sec
Announce messages received from:
  10.196.252.1
Message source:
  10.196.252.1    :   26 messages
  10.196.252.2    :    3 messages
  10.196.252.3    :    6 messages
  10.196.252.4    :    5 messages

Finished reporting after 1 summaries
```

## Usage

As this program relies on packet capture from privileged ports, it must
be granted elevated permissions, or be run as the root user, otherwise
'permission denied' errors will result.

The program may be compiled into an executable binary by running `go build`,
or can be run from the source file using `go run ptp_message_count.go` as
in the example above.

## Options

A description of all command-line options will be given by running:

```
./ptp_message_count -h
```

* -I _interface_

  Network interface from which to capture traffic. [required]

* -V

  Show _version_ and exit.

* -a

  Display announce messages as they are received, rather than waiting for
  the summary results. Useful for real-time feedback on whether there are two
  fighting master clocks in a PTPv2 system. This option is off by default.

* -c _count_

  Stop and exit after _count_ summaries have been reported. The program will
  continues forever if a value of 0 is specified, which is the default.

* -d domain

  Only process messages for the specified PTP domain (0-255). All messages
  will be processed if a negative value is specified, which is the default.

* -i _interval_

  Time interval over which to capture packets between each summary report.
  The time interval must be specified in a form recognised by Go's
  _ParseDuration()_ function, e.g. `10s`, `5m`, `1h30m`. Valid time units are
  "ns", "us" (or "µs"), "ms", "s", "m", "h". The default is 5s.

* -s

  Summarise the source of messages, ordered by IP address. By default this is
  off as the list can be rather long in a large network without boundary
  clocks.

* -v1only

  Monitor only PTPv1 traffic. By default all PTP traffic is monitored.

* -v2only

  Monitor only PTPv2 traffic. By default all PTP traffic is monitored.

## Further Development

This tool started life to show issues in a complex and
unstable PTP distribution network, where a lack of boundary clocks and
network segmentation overloaded the master clock, causing great fragility.
Features and code were added according to the real needs of that project.

There is now opportunity to refactor the code, adopt a more idiomatic coding
style and add features. Pull requests are welcome...

## Author

Nick Prater

## Licence

Copyright (C) 2025 NP Broadcast Limited

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later
version.

This program is distributed in the hope that it will be useful, but WITHOUT
ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with
this program. If not, see <https://www.gnu.org/licenses/>.

