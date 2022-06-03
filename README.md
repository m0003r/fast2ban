# Fast2ban

This is simple fail2ban-like replacement written in Rust.

## Usage:
```bash
./fast2ban # reads default config.toml from current directory
./fast2ban <config.toml location>
```

Emits list of suspicious IPs to stdout, one per line, some information to stderr:

```
Using config file config.toml
Config: Config {
    log_file: "nginx.log",
    log_regex: "^(?P<ip>\\d+\\.\\d+\\.\\d+\\.\\d+) - [^ ]+ \\[(?P<DT>[^\\]]+)\\]",
    requests: 30,
    period: 30,
    date_format: "%d/%B/%Y:%H:%M:%S %z",
}
elapsed 398 ms, 100000 lines parsed, 0 datetime errors, 251256.28140703516 lines/s, banned = 565/3498
```

## Configuration

Example config.toml:
```toml
# log file to parse. Pass '-' to use stdin
log_file = 'nginx.log'

# regexp for parsing log file. Must contain groups <ip> and <DT>, other groups are ignored for now
log_regex = '^(?P<ip>\d+\.\d+\.\d+\.\d+) - [^ ]+ \[(?P<DT>[^\]]+)\] "(\w+) (?P<addr>[^ ]*) HTTP/[\d.]+" (?P<code>\d+) \d+ "[^"]+" "[^"]+" "(?P<UA>[^"]+)'

# maximum number of requests for specific IP for specific time period
requests = 30

# time period in seconds
period = 30

# date format (see https://docs.rs/chrono/0.4.19/chrono/format/strftime/index.html for syntax).
# Note that timezone is required (because of using https://docs.rs/chrono/0.4.19/chrono/struct.DateTime.html#method.parse_from_str method)
date_format = '%d/%B/%Y:%H:%M:%S %z'
```

## Using IPset to efficiently ban IPs

IPset is a fast and efficient way to ban IPs (compared to banning them one by one via separate iptables rules).


1. Create IPset file:
```bash
ipset create banner hash:ip
```

2. Create iptables rule for banning IPs:
```bash
iptables -I INPUT -p tcp -m multiport --dports 80,443 -m set --match-set banner src -j DROP
```

3. Run something like this periodically:
```
# get last queries
tail -n 500000 /var/log/nginx/access.log | grep '/ HTTP/' > nginx.log
# create suspicious IPs list
./fast2ban > ips.txt
# create restore file for IPset
cat ips.txt xargs -n1 echo add banner > ipset-restore.txt
# add IPs to IPset 
ipset restore -exist < ipset-restore.txt

# or in single line:
tail -n 500000 /var/log/nginx/access.log | grep '/ HTTP/' > nginx.log && ./fast2ban | xargs -n1 echo add banner | ipset restore -exist

# or if using log_file = '-' to read from stdin:
tail -n 500000 /var/log/nginx/access.log | grep '/ HTTP/' | ./fast2ban | xargs -n1 echo add banner | ipset restore -exist
```
