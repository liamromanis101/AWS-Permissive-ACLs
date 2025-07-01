# AWS-Permissive-ACLs
Script enumerates security groups and prints out overly permissive ACLs.

## 🔒 Features

- Authenticates using AWS credentials from **environment variables**
- Automatically uses the AWS **region** from environment (`AWS_REGION`)
- Identifies security group **inbound and outbound rules** that:
  - Allow traffic to **broad CIDR blocks**
  - Allow more than **1 usable IP address**
- Outputs:
  - Security group name
  - Rule ID or description
  - Protocol / service
  - Source and destination CIDRs

---

## 🚀 Usage

### 1. 🔧 Prerequisites

- Python 3.6+ (tested on Python 3.13)
- `boto3` (AWS SDK)

Install dependencies:

```bash 
python -m pip install boto3
```

### 2. 🌐 Configure AWS Access

Set these environment variables before running:

```bash
export AWS_ACCESS_KEY_ID=your_access_key
export AWS_SECRET_ACCESS_KEY=your_secret_key
export AWS_REGION=your_region  # e.g., us-west-2
```

### 3. 🏃 Run the script

```bash
python audit_security_groups.py
```

## 🧠 How it Works

The script uses boto3 to retrieve all security groups and their rules. It then evaluates each CIDR block and flags any that:

    Are wider than a single IP (/32)

    Have more than 2 total addresses (to exclude loopback/broadcast cases)

    Commonly overused ranges like:

        0.0.0.0/0 (anywhere)

        10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 (entire private ranges)

## 📦 Example Output
```bash
[!] Insecure Rule Detected:
- Security Group: web-servers-sg
- Rule ID: inbound-0
- Protocol: tcp:22
- Source: 0.0.0.0/0
- Destination: ALL
```

