# BeyondTrust Password Safe API Client

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A robust, thread-safe Python client for interacting with the BeyondTrust Password Safe (PAM) API. Designed for high-concurrency environments and seamless integration with **Robot Framework** and **Automated CI/CD pipelines**.

## 🚀 Key Features

- **Singleton Pattern:** Ensures a single connection pool and token cache across the entire application lifecycle.
- **Automated Token Management:** Handles OAuth2 Bearer token acquisition and background refreshing before expiry.
- **Session Persistence:** Utilizes `requests.Session` for TCP connection pooling, significantly reducing latency for bulk secret retrieval.
- **Thread-Safe:** Implements `threading.Lock` on sensitive token refresh operations to support multi-threaded test execution.
- **Robot Framework Ready:** Includes a streamlined wrapper for direct usage as a test library.

## 🛠 Installation

```bash
git clone [https://github.com/YourUsername/beyondtrust-api-client.git](https://github.com/YourUsername/beyondtrust-api-client.git)
cd beyondtrust-api-client
pip install -r requirements.txt
