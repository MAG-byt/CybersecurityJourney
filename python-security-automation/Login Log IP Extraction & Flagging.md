# Login Log IP Extraction & Flagging

**Category:** Python Security Automation | **Skills:** Python, regular expressions (`re`), loops, log analysis

## Overview

A script that pulls IP addresses out of a raw login log with a regular expression and compares each one against a list of addresses previously flagged for unusual activity. It shows how regex turns unstructured log text into data that can be checked automatically.

## Log Format

Each line holds four space-separated fields:

```
username  date  login-time  ip-address
eraab 2022-05-10 6:03:41 192.168.152.148
```

## How It Works

1. `re.findall()` applies an IP pattern to the whole log and returns every match as a list.
2. The pattern `\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}` means four groups of 1-3 digits separated by literal dots (`\.`).
3. A loop checks each extracted address against `flagged_addresses`.
4. Flagged addresses are reported for further analysis; others are noted as not requiring it.

## Code

```python
import re

# Assign `log_file` to a string containing username, date, login time, and IP address for a series of login attempts
log_file = "eraab 2022-05-10 6:03:41 192.168.152.148 \niuduike 2022-05-09 6:46:40 192.168.22.115 \nsmartell 2022-05-09 19:30:32 192.168.190.178 \narutley 2022-05-12 17:00:59 1923.1689.3.24 \nrjensen 2022-05-11 0:59:26 192.168.213.128 \naestrada 2022-05-09 19:28:12 1924.1680.27.57 \nasundara 2022-05-11 18:38:07 192.168.96.200 \ndkot 2022-05-12 10:52:00 1921.168.1283.75 \nabernard 2022-05-12 23:38:46 19245.168.2345.49 \ncjackson 2022-05-12 19:36:42 192.168.247.153 \njclark 2022-05-10 10:48:02 192.168.174.117 \nalevitsk 2022-05-08 12:09:10 192.16874.1390.176 \njrafael 2022-05-10 22:40:01 192.168.148.115 \nyappiah 2022-05-12 10:37:22 192.168.103.10654 \ndaquino 2022-05-08 7:02:35 192.168.168.144"

# Assign `pattern` to a regular expression that matches IP addresses
pattern = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"

# Use `re.findall()` on `pattern` and `log_file`
valid_ip_addresses = re.findall(pattern, log_file)

# Assign `flagged_addresses` to a list of IP addresses previously flagged for unusual activity
flagged_addresses = ["192.168.190.178", "192.168.96.200", "192.168.174.117", "192.168.168.144"]

# Loop through `valid_ip_addresses` with `address` as the loop variable
for address in valid_ip_addresses:

    # If `address` belongs to `flagged_addresses`, display a flag message
    if address in flagged_addresses:
        print("The IP address", address, "has been flagged for further analysis.")

    # Otherwise, display that no further analysis is needed
    else:
        print("The IP address", address, "does not require further analysis.")
```

## Results

The 15-line log contains **9 well-formed IPs and 6 malformed ones**. Four addresses match the flagged list:

| User | IP address | Result |
| --- | --- | --- |
| smartell | 192.168.190.178 | 🚩 Flagged |
| asundara | 192.168.96.200 | 🚩 Flagged |
| jclark | 192.168.174.117 | 🚩 Flagged |
| daquino | 192.168.168.144 | 🚩 Flagged |

The remaining valid addresses (for example `192.168.152.148` and `192.168.22.115`) produce "does not require further analysis."

## Security Relevance

Matching log data against a watchlist of known-suspicious indicators is a basic form of **indicator-based detection**. Regex is what makes it scalable: the same few lines work on a log of 15 entries or 15 million.

## Limitations & Improvements

- **The pattern matches the right *shape*, not only valid IPs.** Octets above 255 (such as `999.999.999.999`) would still match.
- **Malformed entries are a data-quality finding.** Six addresses are malformed (for example `1923.1689.3.24` and `19245.168.2345.49`). They could be logging errors, corruption, or tampering, so they deserve a look rather than silent discarding.
- **Truncation false positive.** For `192.168.103.10654` (user `yappiah`), the pattern above returns `192.168.103.106`, a shortened address that was never actually in the log, so it appears as a 10th "valid" match.
- **Fix:** add boundaries so a match can't start or end inside a longer run of digits or dots:

```python
pattern = r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])"
```

With this pattern the script returns exactly the 9 well-formed addresses. For strict validation (octets 0-255), pair the regex with Python's built-in `ipaddress` module.
