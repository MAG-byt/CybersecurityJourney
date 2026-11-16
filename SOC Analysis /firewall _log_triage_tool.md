## What this project shows

- **Log triage:** turning thousands of raw rows into a short, ranked list of sources to investigate.
- **Python automation:** a generator, chunked reading, list comprehensions, `argparse`, and tests, packaged as a tool someone else can run.
- **Safe handling of data:** a fully fictitious sample log, with documentation-range IP addresses and planted behaviours (a port scan, SSH brute force, slow RDP probing, and a blocked internal device) so the results can be checked.

- ## Main Concept

```markdown
# log-triage

A small command-line tool that summarises a large firewall log CSV. It counts allowed and denied connections, then ranks the source IPs with the most denied connections and shows how many of those hit sensitive ports (22, 23, 445, 3389). It gives an analyst a short list of "who should I look at first?" instead of thousands of raw rows.

All data in this repository is **fictitious**. No real logs are included.

## What it does

- **Reads the file without loading it all at once.** Actions are counted line by line with a generator, and denied traffic is filtered in pandas chunks, so memory use stays small however big the log is.
- **Counts actions** (`ALLOW` / `DENY`) across the whole file.
- **Ranks denied sources** by number of denied connections, and flags how many of each source's hits were on sensitive ports.
- **Skips malformed lines** instead of crashing.
- **Saves a bar chart** of the top sources if you ask for one.

## Quick start

Requires Python 3.

```bash
git clone https://github.com/YOUR-USERNAME/log-triage.git
cd log-triage
python3 -m pip install -r requirements.txt
python3 logtriage.py sample_firewall_synthetic.csv --top 5 --plot top_denied.png
```

```bash
python3 -m venv venv
source venv/bin/activate
```

### Options

| Option | Meaning |
| --- | --- |
| `path` | The CSV file to analyse (required) |
| `--top N` | How many source IPs to show (default 5) |
| `--chunksize N` | Rows read per chunk (default 1000) |
| `--plot FILE.png` | Also save a bar chart of the top denied sources |

A path is read from the folder your terminal is in, so run the command from the project folder, or give a path that starts from where you are.

### Expected output

```text
Actions: {'ALLOW': 3600, 'DENY': 388}
                denied  sensitive
src_ip                           
203.0.113.50        94          4
198.51.100.23       80         80
192.0.2.77          35         35
192.168.1.23        25          0
198.51.100.114       3          0
```

## Input format

A CSV with a header row and exactly these four columns:

```text
timestamp,src_ip,dst_port,action
2026-11-14 00:00:25,192.168.1.11,8080,ALLOW
2026-11-14 00:00:37,192.168.1.15,443,ALLOW
```

## Sample data

`sample_firewall_synthetic.csv` contains 3,988 rows covering one fictitious day (AI-generated dataset). External addresses come from the reserved documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`), which never belong to real hosts, and internal addresses are generic private `192.168.1.x` addresses.

Four behaviours are planted in it, so you can check the tool finds them:

| Source | What it represents | What to notice |
| --- | --- | --- |
| `203.0.113.50` | A port scanner: many different ports in a short burst | Highest volume, but only 4 of its 94 hits are on sensitive ports |
| `198.51.100.23` | An SSH brute-force source hammering port 22 | All 80 hits are on a sensitive port |
| `192.0.2.77` | A slow RDP prober spread across the day | All 35 hits are on a sensitive port |
| `192.168.1.23` | An internal device blocked sending mail (port 25) | 25 denied hits and 0 sensitive, so a "sensitive only" view would miss it |

The rest is ordinary allowed traffic plus background noise of one to three denied hits per random source. `generate_sample_log.py` recreates the file; it uses a fixed random seed, so it produces the same file every time.

```bash
python3 generate_sample_log.py
```

## How it works

| Function | What it does |
| --- | --- |
| `read_large_file()` | A generator that yields one line of the file at a time |
| `lists2dict()` | Pairs the column names with one row's values to make a dictionary |
| `count_by_field()` | Reads line by line, skips the header and malformed lines, and counts how often each value of a column appears |
| `denied_traffic()` | Reads the file in chunks, keeps only `DENY` rows, and flags sensitive ports with a list comprehension |
| `top_denied_sources()` | Groups denied rows by source IP and ranks them |
| `plot_top()` | Saves a bar chart of the top sources |
| `main()` | Reads the command-line options and calls the functions above in order |

## Project structure

```text
log-triage/
├── README.md
├── requirements.txt
├── logtriage.py
├── generate_sample_log.py
├── sample_firewall_synthetic.csv
└── test_logtriage.py
```
## Code
```

"""logtriage: summarise a large firewall log CSV without loading it all at once."""
import argparse

import matplotlib.pyplot as plt
import pandas as pd

FIELDS = ["timestamp", "src_ip", "dst_port", "action"]
SENSITIVE_PORTS = {22, 23, 445, 3389}


def read_large_file(file_object):
    """A generator function to read a large file lazily."""
    while True:
        data = file_object.readline()
        if not data:
            break
        yield data


def lists2dict(list1, list2):
    """Return a dictionary where list1 provides the keys and list2 the values."""
    return dict(zip(list1, list2))


def count_by_field(path, field):
    """Count how often each value of `field` appears, one line at a time."""
    counts = {}
    with open(path) as file:
        lines = read_large_file(file)
        next(lines, None)  # skip the header row
        for line in lines:
            row = line.strip().split(",")
            if len(row) != len(FIELDS):
                continue  # skip malformed lines
            value = lists2dict(FIELDS, row)[field]
            counts[value] = counts.get(value, 0) + 1
    return counts


def denied_traffic(path, chunksize=1000):
    """Read the file in chunks, keep only DENY rows, flag sensitive ports."""
    pieces = []
    for chunk in pd.read_csv(path, chunksize=chunksize):
        denied = chunk[chunk["action"] == "DENY"].copy()
        denied["sensitive"] = [port in SENSITIVE_PORTS for port in denied["dst_port"]]
        pieces.append(denied)
    if not pieces:
        return pd.DataFrame(columns=FIELDS + ["sensitive"])
    return pd.concat(pieces, ignore_index=True)


def top_denied_sources(denied, n=5):
    """Source IPs with the most denied connections, plus how many hit sensitive ports."""
    grouped = denied.groupby("src_ip").agg(denied=("action", "size"), sensitive=("sensitive", "sum"))
    return grouped.sort_values("denied", ascending=False).head(n)


def plot_top(summary, output):
    summary["denied"].plot(kind="bar", title="Top denied source IPs")
    plt.tight_layout()
    plt.savefig(output)


def main():
    parser = argparse.ArgumentParser(description="Summarise a firewall log CSV.")
    parser.add_argument("path", help="CSV with columns: " + ", ".join(FIELDS))
    parser.add_argument("--top", type=int, default=5, help="how many source IPs to show")
    parser.add_argument("--chunksize", type=int, default=1000)
    parser.add_argument("--plot", metavar="PNG", help="save a bar chart to this file")
    args = parser.parse_args()

    print("Actions:", count_by_field(args.path, "action"))
    summary = top_denied_sources(denied_traffic(args.path, args.chunksize), args.top)
    print(summary)
    if args.plot:
        plot_top(summary, args.plot)


if __name__ == "__main__":
    main()
```


## Tests

```bash
python3 -m pytest -q
```

The tests check that two lists become a dictionary, and that the counter skips the header and a malformed line.

## Limitations

- It assumes exactly the four columns above, in that order.
- It splits lines on plain commas, so quoted fields containing commas are not handled.
- The sensitive-port list (`SENSITIVE_PORTS`) is hard-coded.
- It summarises; it does not detect. There are no thresholds, time windows, or alerts, and deciding that a pattern is a scan or brute force is left to the analyst.

## Ideas for next steps

- Take the field names from the CSV header instead of hard-coding them.
- Make the sensitive-port list a command-line option.
- Add a `--since` timestamp filter.
- Flag any source with more than N denied hits on sensitive ports within five minutes.



