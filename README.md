# Smart-Web-Fuzzer (BETA)
Heuristic web fuzzer with anomaly detection for SQLi, XSS and LFI vulnerabilities.
# Smart Web Fuzzer

Heuristic web application fuzzer with machine learning-based anomaly detection for identifying SQL injection, Cross-Site Scripting (XSS), and Local File Inclusion (LFI) vulnerabilities.

## Features

- **Heuristic Analysis**: Compares responses against baseline to identify anomalies
- **Multi-threaded Architecture**: Configurable concurrent requests for optimal performance
- **Three Detection Modules**: SQL Injection, XSS, LFI with dedicated payload sets
- **Real-time Results**: Live vulnerability reporting with confidence scoring
- **GUI Interface**: Native desktop application built with PyQt6
- **Response Clustering**: DBSCAN algorithm for outlier detection
- **Similarity Analysis**: Levenshtein distance-based response comparison

## Detection Capabilities

| Vulnerability | Detection Method | Confidence Scoring |
|--------------|-----------------|--------------------|
| SQL Injection | Error pattern matching + content similarity | 0-95% |
| XSS | Payload reflection + context detection | 0-90% |
| LFI | File content pattern matching | 0-95% |

## Installation

### Prerequisites

- Python 3.11 or higher
- pip package manager

### Setup

```bash
git clone https://github.com/Ruby251/smart-web-fuzzer.git
cd smart-web-fuzzer
python3 or python smart_fuzzer.py
