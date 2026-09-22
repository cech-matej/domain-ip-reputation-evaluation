from collectors.base.api_collector import APICollector
from config.settings import OPENTIP_KASPERSKY_API_KEY
from utils.ip import is_ipv4, is_ipv6
from utils.verdict import Verdict


class OpentipKasperskyCollector(APICollector):
    name = "opentip_kaspersky"

    supports_domain = True
    supports_ipv4 = True
    supports_ipv6 = False

    BASE_URL = "https://opentip.kaspersky.com"
    ENDPOINT_BASE = "/api/v1/search/"
    ENDPOINT_IP = "ip"
    ENDPOINT_DN = "domain"

    def __init__(self):
        super().__init__()
        self.api_key = OPENTIP_KASPERSKY_API_KEY

    @staticmethod
    def is_rate_limited(response):
        # OpenTIP Kaspersky uses 403 for rate limiting; 429 is included for safety/future-proofing
        return response.status_code in (403, 429)

    def collect(self, address: str) -> dict:
        headers = {
            "accept": "application/json",
            "x-api-key": self.api_key,
        }

        if is_ipv4(address) or is_ipv6(address):
            self.ENDPOINT = self.ENDPOINT_BASE + self.ENDPOINT_IP
        else:
            self.ENDPOINT = self.ENDPOINT_BASE + self.ENDPOINT_DN

        response = self.session.get(f"{self.url()}?request={address}", headers=headers)

        self.validate_response(response)

        return response.json()

    def classify(self, data: dict) -> Verdict:
        zone = data.get("Zone")

        if zone == "Grey":
            return Verdict.NO_DATA
        elif zone == "Green":
            return Verdict.BENIGN
        elif zone in ["Yellow", "Orange"]:
            return Verdict.SUSPICIOUS

        return Verdict.MALICIOUS

