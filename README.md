# Threat Intelligence Aggregator

The Threat Intelligence Aggregator collects and aggregates threat intelligence data from multiple external services. It supports API-based collection, DNS-based analysis, and HTML scraping, with a standardized classification system and visualization of results.

The framework is designed to make it easy to add new threat intelligence sources while minimizing unnecessary API requests through caching and supporting mock APIs for development and testing.

## Features

* Collect threat intelligence from multiple external services.
* Support for API-based, DNS-based, and HTML-based collectors.
* Standardized threat classification using `Verdict`.
* Configurable support for domains, IPv4 addresses, and IPv6 addresses.
* Automatic switching between real APIs and mock APIs.
* Response caching to reduce duplicate requests and API usage.
* Rate-limit detection for API-based collectors.
* JSON output for collected data.
* Visualization of domain, IPv4, and IPv6 results.
* Extensible collector registry.

## Project Structure

```text
.
├── collectors/
│   ├── api/
│   │   └── <collector_files>.py     # Concrete API collector implementations
│   ├── base/
│   │   ├── api_collector.py         # Base class for API collectors
│   │   ├── base_collector.py        # Core abstract collector
│   │   ├── dns_collector.py         # Base class for DNS collectors
│   │   └── html_collector.py        # Base class for HTML collectors
│   ├── dns/
│   │   └── <collector_files>.py     # Concrete DNS collector implementations
│   ├── html/
│   │   └── <collector_files>.py     # Concrete HTML collector implementations
│   ├── visualization/               # Visualization utilities
│   ├── collector_runner.py          # Collection orchestration, caching, and output generation
│   └── registry.py                  # Registered collectors
│
├── config/
│   └── settings.py                  # Configuration and environment variables
│
├── mock_api/                        # Flask-based mock API
│
├── utils/
│   ├── cache.py                     # Persistent collector cache management
│   ├── exceptions.py                # Custom application exceptions
│   ├── input.py                     # Input JSON loading utilities
│   ├── ip.py                        # IP address validation and utilities
│   ├── output.py                    # Output directory creation utilities
│   └── verdict.py                   # Standardized verdict definitions
│
├── main.py                          # Application entry point
├── requirements.txt                 # Python dependencies
├── .env.example                     # Environment variable template
├── cache/                           # Generated persistent cache files
└── output/                          # Generated collector results
```


---

## Setup

### 1. Create `.env` file

Copy the example environment file:

```bash
cp .env.example .env
```

Fill in the required API keys and configuration values.

### 2. Configure settings

Review and adjust:

```
config/settings.py
```

This file contains configurations such as:

* API keys loaded from `.env`.
* Mock API configuration.
* Feature flags (e.g. `USE_MOCK_API`).
* Other application settings.

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

---

## Configuration

Configuration is managed through environment variables and `config/settings.py`.

### Mock API mode

The framework supports switching between real external services and mock APIs.

Relevant settings include:

| Setting         | Description                                            |
| --------------- | ------------------------------------------------------ |
| `USE_MOCK_API`  | Enables or disables mock API mode.                     |
| `MOCK_API_BASE` | Base URL used to construct mock collector endpoints.   |
| API keys        | Credentials for external threat intelligence services. |

When mock mode is enabled, collectors using `self.url()` automatically target the mock API base.

---

## Usage

### Specify input file in `main.py`
Before running the data collection, you need to provide a JSON file containing the domains to analyze.
Update the `main.py` call to `load_domains()` with the path to your input file.

#### Input file format (example test_domains.json)
```json
[
  {
    "domain_name": "test.com",
    "A": [
      "8.8.8.8",
      "9.9.9.9"
    ],
    "AAAA": [
      "2001:4860:4860::8888"
    ]
  },
  {
    "domain_name": "test2.com",
    "A": [
      "8.8.8.8"
    ],
    "AAAA": [
      "2001:4860:4860::8888"
    ]
  }
]
```

### Run data collection

```bash
python main.py
```

The application will:

* Load the configured input domains and IP addresses.
* Run collectors specified in the `collectors = [ ... ]` list in `main.py`.
* Collect data from the relevant external services.
* Apply caching.
* Save the results to the output directory (e.g. `output/`).

---

### Generate visualizations

The visualization module loads existing JSON results, classifies collected data, and generates charts.

```python
from utils.visualize import visualize

visualize("output_folder_path")
```

The visualization process:

* Loads existing JSON files.
* Applies collector classification.
* Groups results by target type.
* Generates bar charts for supported data types.

The supported visualization categories are:

* Domains
* IPv4 addresses
* IPv6 addresses

### Visualization rules

* A collector is included only for the target types it supports.
* `supports_domain` controls inclusion in domain visualizations.
* `supports_ipv4` controls inclusion in IPv4 visualizations.
* `supports_ipv6` controls inclusion in IPv6 visualizations.
* Collectors without usable data are excluded from the relevant charts.

---

## Caching and Rate Limits

The framework is designed to minimize unnecessary API requests and reduce the risk of exceeding service rate limits.

### Caching

Where caching is implemented by the collection framework:

* Repeated requests for the same domain can reuse cached results.
* Repeated requests for the same IPv4 address can reuse cached results.
* Repeated requests for the same IPv6 address can reuse cached results.
* Domains and IP addresses are handled separately according to collector capabilities.

For example, if multiple domains resolve to the same IPv4 address, the framework can reuse the result of a previous lookup rather than querying the service again.

### Rate-limit handling

`APICollector` provides a `validate_response()` method that detects rate-limited responses.

By default, an HTTP `429` response raises:

```python
RateLimitException
```

Collectors or the application pipeline may implement additional retry, backoff, or error-handling behavior.

---

## Verdict Classification

Threat intelligence results are normalized using the `Verdict` definitions in:

```text
utils/verdict.py
```

The supported verdicts are:

| Verdict      | Meaning                                                                           |
| ------------ | --------------------------------------------------------------------------------- |
| `NO_DATA`    | No usable intelligence data is available.                                         |
| `BENIGN`     | The collected data does not indicate a threat according to the collector's logic. |
| `SUSPICIOUS` | The collected data contains indicators that require further investigation.        |
| `MALICIOUS`  | The collected data meets the collector's criteria for a malicious result.         |

Classification thresholds and detection logic are collector-specific.

---

## Collector Architecture

Collectors are organized into a hierarchy of abstract base classes. Each concrete collector inherits from one of the specialized collector types and implements the required methods.

```text
BaseCollector
├── APICollector
│   └── Concrete API collectors
├── DNSCollector
│   └── Concrete DNS collectors
└── HTMLCollector
    └── Concrete HTML collectors
```

### `BaseCollector`

Located in:

```text
collectors/base/base_collector.py
```

`BaseCollector` defines the common interface and functionality shared by all collectors.

#### Responsibilities

* Define the collector name.
* Declare supported target types.
* Require implementations of `collect()` and `classify()`.
* Build the collector URL.
* Provide default rate-limit detection.

`BASE_URL` and `ENDPOINT` are combined by the `url()` method to construct the collector's request URL.

When `USE_MOCK_API` is enabled, the URL is automatically built using `MOCK_API_BASE` and the collector's `name`.

For example, the resulting URL is conceptually:

```text
<MOCK_API_BASE>/<collector_name><ENDPOINT>
```

#### Supported target flags

| Flag              | Description                               |
| ----------------- | ----------------------------------------- |
| `supports_domain` | The collector can analyze domain names.   |
| `supports_ipv4`   | The collector can analyze IPv4 addresses. |
| `supports_ipv6`   | The collector can analyze IPv6 addresses. |

### Abstract methods

Every concrete collector must implement:

```python
def collect(self, address: str) -> dict:
    """Collect raw data for the specified address."""
    pass

def classify(self, data: dict):
    """Convert collected data into a standardized verdict."""
    pass
```

`collect()` should return raw data as a dictionary. Classification should be handled separately by `classify()`.

---

## Collector Types

### 1. `APICollector`

Located in:

```text
collectors/base/api_collector.py
```

`APICollector` is the base class for collectors that communicate with external HTTP APIs.

#### Responsibilities

* Create a `requests.Session()` for API requests.
* Provide a shared API collector interface.
* Validate responses for rate limiting.
* Raise `RateLimitException` when the API returns a rate-limit response.

By default, HTTP status code `429` is treated as a rate-limit response.

### 2. `DNSCollector`

Located in:

```text
collectors/base/dns_collector.py
```

`DNSCollector` is the base class for collectors that perform DNS lookups.

#### Responsibilities

* Create a DNS resolver using `dns.resolver.Resolver()`.
* Provide a helper method for resolving DNS records.
* Support DNS record types such as `A`, `AAAA`, `MX`, and `TXT`.
* Provide an HTTP session when mock API mode is enabled.

### 3. `HTMLCollector`

Located in:

```text
collectors/base/html_collector.py
```

`HTMLCollector` is the base class for collectors that scrape and analyze HTML content from webpages.

#### Responsibilities

* Define a common interface for HTML-based collectors.
* Provide a helper for retrieving and parsing webpage content.
* Use `BeautifulSoup` to parse HTML documents.

---

## Implementing a New Collector

Collectors are the core building blocks of this project. Each collector integrates one external service.

### 1. Choose the appropriate base class

Select the class that matches the type of data source:

| Collector type  | Use case                                       |
| --------------- | ---------------------------------------------- |
| `APICollector`  | Collecting data from an HTTP API.              |
| `DNSCollector`  | Performing DNS lookups and DNS-based analysis. |
| `HTMLCollector` | Scraping and analyzing webpage content.        |

### 2. Create a new collector file

Create a new Python file in the collectors directory:

```
collectors/<collector_type>/<my_collector>.py
```

### 3. Inherit from the appropriate base class

For example:

```python
from collectors.base.api_collector import APICollector
from utils.verdict import Verdict


class MyCollector(APICollector):
    name = "my_collector"

    BASE_URL = "https://api.example.com"
    ENDPOINT = "/v1/check"

    # Set these flags based on the types of data the service provides:
    # - supports_domain: True if the service can provide data about domain names
    # - supports_ipv4: True if the service can provide data about IPv4 addresses
    # - supports_ipv6: True if the service can provide data about IPv6 addresses
    # Only the supported data types will be included in the visualizations
    supports_domain = True
    supports_ipv4 = True
    supports_ipv6 = False
```

Use the appropriate base class for DNS or HTML collectors instead.

### 4. Implement `collect()`

The `collect()` method receives a domain or IP address and returns raw data.

```python
def collect(self, target: str) -> dict:
    response = self.session.get(
        self.url(),
        params={"q": target},
    )

    self.validate_response(response)

    if not response.ok:
        return {}

    return response.json()
```

**Important:**

* Always return a dictionary.
* Do not classify data inside `collect()`.
* Preserve relevant raw response data for later processing.
* Handle failed requests appropriately.
* Use `self.url()` instead of hardcoding mock and production URLs.

---

### 5. Implement `classify()`

The `classify()` method converts raw collector data into a standardized verdict.

```python
def classify(self, data: dict) -> Verdict:
    score = data.get("score", -1)

    if score < 0:
        return Verdict.NO_DATA
    elif score < 10:
        return Verdict.BENIGN
    elif score < 50:
        return Verdict.SUSPICIOUS
    else:
        return Verdict.MALICIOUS
```

The classification thresholds above are only examples. Each collector should define classification logic appropriate to its data source.

The method must return one of the supported values:

* `Verdict.NO_DATA`
* `Verdict.BENIGN`
* `Verdict.SUSPICIOUS`
* `Verdict.MALICIOUS`

---

### 6. Register the collector

Add your collector to:

```
collectors/registry.py
```

```python
from collectors.api.my_collector import MyCollector

def get_all_collectors():
    return [
        ...
        MyCollector(),
    ]
```

The registry defines the collectors that are available to the application.

Use the appropriate collector directory (`api`, `dns`, or `html`) depending on the type of collector.

### 7. Add the collector to the pipeline

Registering the collector in `registry.py` makes it available to the project, but the collector must also be added to the collector list in `main.py` in order to be executed when the pipeline runs.

In `main.py`, add an instance of your collector to the `collectors` list:

```python
collectors = [
    ...
    MyCollector(),
]
```

Make sure the collector is imported at the top of `main.py`:

```python
from collectors.api.my_collector import MyCollector
```

Use the appropriate collector directory (`api`, `dns`, or `html`) depending on the type of collector.

#### Registration vs. Pipeline Execution

These two steps serve different purposes:

| Location                 | Purpose                                                                                        |
| ------------------------ | ---------------------------------------------------------------------------------------------- |
| `collectors/registry.py` | Registers the collector as part of the application's available collectors.                     |
| `main.py`                | Adds the collector to the pipeline so it is instantiated and executed during a collection run. |

Therefore, a new collector should be added to **both** places when the project architecture requires both registration and explicit pipeline inclusion.

### 8. Verify the collector

After registering and adding the collector to `main.py`, run the pipeline:

```bash
python main.py
```

Verify that the collector:

* Is instantiated successfully.
* Is executed by the pipeline.
* Produces the expected output.
* Uses the correct cache file.
* Handles supported domains, IPv4 addresses, and/or IPv6 addresses correctly.
* Produces the expected `Verdict` during classification.
* Appears in visualizations when applicable.

Your new collector is now part of the collection pipeline.

---

## Development Guidelines

When implementing or modifying collectors:

* Keep collection and classification separate.
* Use the appropriate specialized base class.
* Return consistent data structures.
* Handle API errors and missing data gracefully.
* Avoid hardcoding API keys.
* Use configuration values from `.env` and `config/settings.py`.
* Respect external service rate limits.
* Document any service-specific response formats and classification rules.

---

## Testing

Before contributing a new collector, verify its behavior using mock APIs or test fixtures where possible.

Recommended tests include:

* Successful data collection.
* Failed HTTP requests.
* Invalid or missing API keys.
* Rate-limit responses.
* Empty API responses.
* DNS resolution failures.
* HTML scraping failures.
* Classification of all supported verdicts.
* Correct handling of supported target types.
* Cache reuse for repeated targets.

---

## Notes

* Not all collectors support domains, IPv4 addresses, and IPv6 addresses.
* Unsupported target types should be excluded from irrelevant collection and visualization operations.
* Missing or invalid API keys may result in empty outputs or failed requests.
* The behavior of individual collectors depends on the external service they integrate with.
* Mock API mode is intended for development and testing.
* Do not commit API keys or other secrets to the repository.
