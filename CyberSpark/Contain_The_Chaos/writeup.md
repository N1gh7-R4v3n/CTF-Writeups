# Contain The Chaos — Full Writeup

- **Challenge Author:** N1gh7R4v3n   
- **Category:** Misc (Fork Bomb / Process Isolation)
- **Difficulty:** Easy
- **Flag:** `Spark{nproc_Pr3v3n75_7h3_B0m8F0rk_C0n741n3r5_n33d_l1m175_700_#F84ng4}`

---

## 1. Challenge Overview

![Contain the chaos page](screenshots/containTheChaos.png.png)

**Contain the Chaos** is a two-stage Linux process isolation challenge. Players connect via netcat to a Docker container simulating a server that suffered a fork bomb attack. The task is to investigate the incident and apply proper process limits at two levels:

1. **OS level (PAM nproc)** — Edit `limits.conf` to prevent fork bombs via user process limits
2. **Container level (pids-limit)** — Construct a `docker run` command with `--pids-limit` to contain processes at the container level

### Challenge Environment

Connecting to the challenge:

```bash
nc 3.249.73.207 5842
```

We are dropped into a shell as a random user (`player1`–`player30`):

```
=============================================

          CONTAIN THE CHAOS
          Topic: Fork Bomb Prevention

=============================================

System status: UNSTABLE.
A critical incident occurred on the previous shift.
You have 30 minutes to stop this attack.

Your credentials grant you access to the shell.
Documentation has been left in the home directory.

Two flags to find. Good luck.
---------------------------------------------
```

### Challenge Files

No files are provided to the player — all investigation happens inside the container via shell commands.

---

## 2. Reconnaissance & Enumeration

### Reading the Incident Report

```bash
player29@ctf-server:~$ cat ~/incident_report.txt
```

```
INCIDENT REPORT --- 2026-05-15
System became completely unresponsive at 14:32.
All shells froze. SSH connections timed out.
Root cause: runaway process replication.
Action required: harden process limits.
Status: UNRESOLVED --- awaiting trainee fix.
```

The report confirms the root cause: **runaway process replication** — a fork bomb. No limits were in place to stop it.

### Checking the Todo

```bash
player29@ctf-server:~$ cat ~/todo.txt
```

```
- [x] Investigate yesterday's crash
- [ ] Review process limits
- [ ] Apply fix before next shift
```

The only unchecked item is **"Review process limits"** — pointing us toward process limit configuration.

### Examining Current Limits

```bash
player29@ctf-server:~$ cat ~/limits.conf
```

```
# System process limits configuration
# WARNING: nproc limits were removed during maintenance

* soft nofile 1024
* hard nofile 1024
# Put your nproc command under this
```

The `limits.conf` file has **nproc entries deliberately removed** (the warning admits this). Only `nofile` (file descriptor) limits exist, but `nproc` (max user processes) is absent — a dead giveaway that this is what needs to be fixed.

### Discovering the Validation Script

```bash
player29@ctf-server:~$ ls -la
```

We find `validate.sh` and `bonus.sh` in the home directory — these are the gatekeepers for the two flags.

---

## 3. Vulnerability Analysis

### Vulnerability 1: Missing nproc Limit (OS Level)

**Observation**: The `limits.conf` file explicitly states that nproc limits were "removed during maintenance." Without a `nproc` entry in PAM's `limits.conf`, any user can spawn an unlimited number of processes — the exact precondition for a fork bomb.

The PAM `pam_limits.so` module enforces the limits defined in `/etc/security/limits.conf` (or in this case, the project's local `limits.conf`). The syntax is:

```
<domain> <type> <item> <value>
```

Where:
- `<domain>`: `*` for all users, or a specific user
- `<type>`: `soft` (warning limit) or `hard` (absolute ceiling)
- `<item>`: `nproc` (max user processes)
- `<value>`: numeric limit

The expected fix requires:
- A soft nproc limit (≥ 1 and ≤ 50)
- A hard nproc limit (≥ 1 and ≤ 50)
- Both values must be **equal** (prevents privilege escalation via `ulimit`)

### Vulnerability 2: Missing Container pids-limit (Container Level)

**Observation**: The `bonus.sh` script requires constructing a `docker run` command with `--pids-limit`. Without this flag, a container can exhaust host process IDs, escaping the container's resource isolation.

Docker's `--pids-limit` flag caps the maximum number of PIDs (processes) a container can create. A value ≤ 50 is required, ensuring that even if a fork bomb executes inside the container, it cannot take down the host.

---

## 4. Exploit Development

### Stage 1 — nproc Limits (OS Level)

**The Fix**: Append nproc limits to the config:

```bash
echo "* soft nproc 30" >> ~/limits.conf
echo "* hard nproc 30" >> ~/limits.conf
```

This sets both soft and hard limits to 30, meaning no user can spawn more than 30 concurrent processes — enough for normal operation, but far below fork bomb levels.

**Validation**:

```bash
player29@ctf-server:~$ ~/validate.sh
```

```
[✓] Checking soft nproc limit... PASS (30)

[✓] Checking hard nproc limit... PASS (30)

[✓] Hard limit is 50 or below... PASS

[✓] Soft equals hard limit... PASS

Calling validator...

Congratulations! First flag: Spark{nproc_Pr3v3n75_7h3_B0m8F0rk_
```

### Behind the Scenes — How Validation Works

The `reveal` SUID binary (`/usr/local/bin/reveal`) reads the player's `~/limits.conf`, parses the nproc values, and validates them:

- `soft_val < 1 || > 50` → fail
- `hard_val < 1 || > 50` → fail
- `soft_val != hard_val` → fail (must be equal)
- On success: writes a stage marker to `/root/.stage1_<user>` and prints flag1

```c
// From reveal.c — validation logic
if (soft_val < 1 || soft_val > 50) return -4;
if (hard_val < 1 || hard_val > 50) return -5;
if (soft_val != hard_val) return -6;
```

### Stage 2 — Container pids-limit

**The Challenge**: After Stage 1, we run `~/bonus.sh` with a Docker command that includes `--pids-limit`.

The `bonus.sh` script:
1. Verifies Stage 1 is completed (checks for the stage marker)
2. Parses the argument for `docker run` with `--pids-limit <value>`
3. Validates the value is ≤ 50
4. Calls `reveal 2 <value>` to dispense the second flag

**The Solution**:

```bash
~/bonus.sh "docker run --pids-limit 30 ubuntu:22.04 bash"
```

```
Second flag:
C0n741n3r5_n33d_l1m175_700_#F84ng4}

Full flag: Spark{nproc_Pr3v3n75_7h3_B0m8F0rk_C0n741n3r5_n33d_l1m175_700_#F84ng4}
```

---

## 5. Full Exploit Code

### Interactive Solution

```bash
# Stage 1: Set nproc limits
echo "* soft nproc 30" >> ~/limits.conf
echo "* hard nproc 30" >> ~/limits.conf

# Validate
~/validate.sh

# Stage 2: Set container pids-limit
~/bonus.sh "docker run --pids-limit 30 ubuntu:22.04 bash"
```

### Shell One-Liner

```bash
echo "* soft nproc 30" >> ~/limits.conf && echo "* hard nproc 30" >> ~/limits.conf && ~/validate.sh && ~/bonus.sh "docker run --pids-limit 30 ubuntu:22.04 bash"
```

---

## 6. Mitigation Recommendations

| Issue | Vulnerability | Mitigation |
|-------|--------------|------------|
| **Missing nproc Limit** | Any user can spawn unlimited processes | Always set both `soft` and `hard` nproc limits in `limits.conf` |
| **Weak Limit Values** | Limit too high still allows abuse | Keep limits ≤ 50; tune based on expected workload |
| **Soft != Hard** | Users can override soft limit with `ulimit -u` | Always set `soft` == `hard` to prevent escalation |
| **No Container pids-limit** | Fork bomb inside container can exhaust host PIDs | Always use `--pids-limit` in production containers |
| **Missing Defense in Depth** | Single layer of protection is insufficient | Enforce limits at both OS (PAM) and container (Docker) levels |

---

## 7. Lessons Learned

### What Makes This Challenge Interesting

1. **Two-layer privilege escalation**: The challenge teaches that process limits must be enforced at multiple levels — OS-level (PAM nproc) and container-level (Docker pids-limit). A fork bomb can escape a container if only one layer is protected.

2. **Real incident investigation**: Players are dropped into an active incident scenario with a report to read and a todo list, mimicking a real-world forensics and remediation workflow.

3. **SUID binary as gatekeeper**: The `reveal` binary is the only privileged path to the flag, properly gated by validating the player's config file — demonstrating secure privilege elevation patterns.

4. **Equal limits best practice**: Requiring `soft == hard` teaches an important security hardening principle — users can bypass soft limits with `ulimit -u`, so both must match.

### Vulnerability Classes

- **CWE-770**: Allocation of Resources Without Limits or Throttling
- **CWE-834**: Excessive Iteration
- **CWE-400**: Uncontrolled Resource Consumption
- **CWE-20**: Improper Input Validation

---

## 8. References

- `limits.conf(5)` — Linux PAM documentation
- [Docker `--pids-limit` flag documentation](https://docs.docker.com/engine/containers/resource_constraints/)
- [OWASP: Denial of Service — Fork Bomb Prevention](https://owasp.org/www-community/attacks/Denial_of_Service)
- [Fork bomb on Wikipedia](https://en.wikipedia.org/wiki/Fork_bomb)
- [PAM limits.conf documentation](https://linux.die.net/man/5/limits.conf)

---

### Challenge Author

- **Author**: [N1gh7R4v3n]
- [LinkedIn](https://www.linkedin.com/in/n1gh7r4v3n/)

