# go-sql-sniffer

The go-sql-sniffer extracts the SQL packet from tcpdump packet. The tool wraps tcpdump.

# Installation

Run git clone and go build.

# Usage

* run

```
sudo go-sql-sniffer
```

It is same as `tcpdump tcp -i any -A -t -n -q -s 0 dst port 3306`. The output will be humanreadable json string.

```
{"unixtime":1497694222,"datetime":"2017-06-17 10:10:22","from":"10.0.4.218.61904","to":"10.0.0.159.3306","sql":"SELECT `t`.* FROM `t` WHERE `t`.`id` IN (25298241, 25505237, 25563426, 25564627, 25053459, 25505323, 25506064, 25566828, 24280930, 25568604, 25569780)"}
```

* options

```
Usage of /tmp/go-sql-sniffer:
  -dst
        The dst flag. See man tcpdump. (default true)
  -src
        The src flag. See man tcpdump.
  -port string
        The SQL traffic port. (default "3306")
  -file string
        If you run with -file, the packet data will be saved to specified file.
  -format string
        The output format. You can set json, csv and tsv. (default "json")
```

# License

MIT