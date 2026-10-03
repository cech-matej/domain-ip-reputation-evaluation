from collectors.base.api_collector import APICollector
from config.settings import HYBRID_ANALYSIS_API_KEY
from utils.ip import is_ipv4, is_ipv6
from utils.verdict import Verdict


class HybridAnalysisCollector(APICollector):
    name = "hybrid_analysis"

    supports_domain = True
    supports_ipv4 = False
    supports_ipv6 = False

    BASE_URL = "https://hybrid-analysis.com"
    ENDPOINT = "/api/v2/search/terms"  # target sent in POST body

    def __init__(self):
        super().__init__()
        self.api_key = HYBRID_ANALYSIS_API_KEY

    def collect(self, address: str) -> dict:
        headers = {
            "accept": "application/json",
            "api-key": self.api_key,
        }

        # Decide whether IP or domain
        if is_ipv4(address) or is_ipv6(address):
            post_data = {"host": address}
        else:
            post_data = {"domain": address}

        response = self.session.post(f"{self.url()}", headers=headers, data=post_data)

        self.validate_response(response)

        # Initialize counters
        malicious_cnt = 0
        suspicious_cnt = 0
        no_threat_cnt = 0
        whitelisted_cnt = 0
        worst_score = -1
        best_score = -1
        sum_score = 0
        null_score_cnt = 0

        if response.ok:
            json_response = response.json()
            data = json_response.get("result", [])
            data_len = len(data)

            worst_score = -1 if data_len == 0 else 0
            best_score = -1 if data_len == 0 else 100

            changed_score = False

            for single_result in data:
                verdict = (single_result.get("verdict") or "").lower()

                if verdict == "malicious":
                    malicious_cnt += 1
                elif verdict == "suspicious":
                    suspicious_cnt += 1
                elif verdict == "whitelisted":
                    whitelisted_cnt += 1
                elif verdict == "no specific threat":
                    no_threat_cnt += 1

                threat_score = single_result.get("threat_score")
                if threat_score is None:
                    null_score_cnt += 1
                else:
                    changed_score = True
                    sum_score += threat_score

                    if worst_score is None or threat_score > worst_score:
                        worst_score = threat_score
                    if best_score is None or threat_score < best_score:
                        best_score = threat_score

            if not changed_score:
                worst_score = -1
                best_score = -1

            avg_score = 0 if (data_len == 0 or data_len - null_score_cnt == 0) else sum_score / (data_len - null_score_cnt)

            # Add calculated/extracted properties to the original response
            json_response["_extracted"] = {
                "malicious_cnt": malicious_cnt,
                "suspicious_cnt": suspicious_cnt,
                "no_threat_cnt": no_threat_cnt,
                "whitelisted_cnt": whitelisted_cnt,
                "worst_score": worst_score,
                "best_score": best_score,
                "avg_score": avg_score,
                "null_score_cnt": null_score_cnt,
            }

            return json_response
        else:
            # Preserve the same response structure even when the request fails
            return {
                "_extracted": {
                    "malicious_cnt": -1,
                    "suspicious_cnt": -1,
                    "no_threat_cnt": -1,
                    "whitelisted_cnt": -1,
                    "worst_score": -1,
                    "best_score": -1,
                    "avg_score": -1,
                    "null_score_cnt": -1,
                }
            }

    def classify(self, data: dict) -> Verdict:
        extracted = data.get("_extracted", {})
        worst_score = extracted.get("worst_score", -1)

        if worst_score < 0:
            return Verdict.NO_DATA
        elif worst_score < 10:
            return Verdict.BENIGN
        elif worst_score < 50:
            return Verdict.SUSPICIOUS
        else:
            return Verdict.MALICIOUS