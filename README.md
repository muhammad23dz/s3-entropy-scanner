# S3 Entropy Scanner

[![Python: 3.9+](https://img.shields.io/badge/Python-3.9+-yellow)](https://www.python.org/)
[![Security: Shannon Entropy](https://img.shields.io/badge/Security-Probabilistic-blue)](https://en.wikipedia.org/wiki/Entropy_(information_theory))

A CLI tool that scans S3 buckets for high-entropy strings (potential leaked API keys, certificates, or tokens) using Shannon Entropy mathematics.

## Problem Statement

Regular expressions (RegEx) are great for finding secrets with known formats (like AWS `AKIA...`). However, they fail to detect:
1.  Rotated keys with custom prefixes.
2.  High-randomness strings from internal or proprietary platforms.
3.  Asymmetric private keys.

This tool solves this by measuring the **information density** of strings.

## Installation

```bash
git clone https://github.com/muhammad23dz/s3-entropy-scanner
cd s3-entropy-scanner
pip install -r requirements.txt
```

## Usage

```bash
python scanner.py --bucket protected-data-prod --threshold 4.8
```

## How It Works

The engine calculates the Shannon Entropy $H(X)$ for every line in the scanned objects:
$$H(X) = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$$

Strings with $H(X) > 4.5$ are flagged for human review, as standard English typically sits below $3.5$.

## Performance

The scanner uses `boto3` paginators and thread pools to handle buckets with millions of objects. It includes a `blacklist` for binary file types (`.png`, `.jpg`, `.pdf`) to avoid false positive spikes.

## License
MIT
