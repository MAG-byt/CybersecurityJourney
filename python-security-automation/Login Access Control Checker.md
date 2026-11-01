# Login Access Control Checker

**Category:** Python Security Automation | **Skills:** Python, conditional logic, lists, functions

## Overview

A small Python function that checks a login attempt against two approved lists: usernames and the device ID registered to each user. It separates three outcomes: an unapproved user, an approved user on their assigned device, and an approved user on the wrong device.

## How It Works

1. `approved_users` and `approved_devices` are parallel lists, so the device at index *n* belongs to the user at index *n*.
2. `login(username, device_id)` first checks whether the username is approved.
3. If approved, it looks up the user's index and compares the supplied device ID with the registered one.
4. If the username is not approved, it denies access.

## Code

```python
# Assign `approved_users` to a list of approved usernames
approved_users = ["elarson", "bmoreno", "sgilmore", "eraab", "gesparza"]

# Assign `approved_devices` to a list of device IDs that correspond to the usernames in `approved_users`
approved_devices = ["8rp2k75", "hl0s5o1", "4n482ts", "a307vir", "3rcv4w6"]

# Define a function named `login` that takes in two parameters, `username` and `device_id`
def login(username, device_id):

    # If `username` belongs to `approved_users`,
    if username in approved_users:
        print("The user", username, "is approved to access the system.")

        # assign `ind` to the index of `username` in `approved_users`
        ind = approved_users.index(username)

        # If `device_id` matches the element at the index `ind` in `approved_devices`,
        if device_id == approved_devices[ind]:
            print(device_id, "is the assigned device for", username)
        else:
            print(device_id, "is not their assigned device.")

    # Otherwise, `username` does not belong to `approved_users`
    else:
        print("The username", username, "is not approved to access the system.")

# Call the function with different username and device_id combinations
login("bmoreno", "hl0s5o1")
login("elarson", "r2s5r9g")
login("abernard", "4n482ts")
```

## Test Results

| Call | Output | Interpretation |
| --- | --- | --- |
| `login("bmoreno", "hl0s5o1")` | Approved; assigned device | Expected, legitimate login |
| `login("elarson", "r2s5r9g")` | Approved; **not** their assigned device | Valid user on an unregistered device, which could mean shared or stolen credentials |
| `login("abernard", "4n482ts")` | **Not approved** | Unknown user. The device ID `4n482ts` is actually registered to `sgilmore`. |

## Security Relevance

This is a simplified model of **allowlisting** and **device binding**. A correct username alone isn't enough: the request also has to come from the device registered to that user. Mismatches like the second test are the kind of event an analyst would investigate.

## Limitations & Improvements

- **Parallel lists are fragile.** If one list is edited without the other, users and devices silently misalign. A dictionary (`{username: device_id}`) keeps each pair together.
- **The script doesn't notice the `abernard` case.** An unapproved user presenting another user's device is an anomaly worth flagging, but the script only denies access.
- **Exact matching only.** `"BMoreno"` or `"bmoreno "` would be rejected, so normalise input (`.strip().lower()`) before comparing.
- **Output only.** A real version would write to a log or raise an alert.

A dictionary-based version of the same logic:

```python
approved_access = {
    "elarson": "8rp2k75", "bmoreno": "hl0s5o1", "sgilmore": "4n482ts",
    "eraab": "a307vir", "gesparza": "3rcv4w6",
}

def login(username, device_id):
    if username not in approved_access:
        print("The user", username, "is not approved to access the system.")
        return
    print("The user", username, "is approved to access the system.")
    if device_id == approved_access[username]:
        print(device_id, "is the assigned device for", username)
    else:
        print(device_id, "is not their assigned device.")
```
