from fastapi import APIRouter
from app.core.registry import get_connector_catalog
from app.services.cache import ping as redis_ping
from app.services import ai

router = APIRouter()

_KEY_URLS = {
    "virustotal": "https://www.virustotal.com/gui/join-us",
    "abuseipdb": "https://www.abuseipdb.com/register",
    "otx": "https://otx.alienvault.com/api",
    "urlscan": "https://urlscan.io/user/signup",
    "censys": "https://censys.io/register",
    "shodan": "https://account.shodan.io",
    "threatfox": "https://threatfox.abuse.ch/api/",
}

_CONNECTOR_LABELS = {
    "shodan_internetdb": "Shodan InternetDB",
    "ip_api": "ip-api.com",
    "abuseipdb": "AbuseIPDB",
    "censys": "Censys",
    "shodan": "Shodan",
    "rdap": "RDAP / Whois",
    "crtsh": "crt.sh",
    "pulsedive": "Pulsedive",
    "virustotal": "VirusTotal",
    "otx": "AlienVault OTX",
    "urlscan": "URLScan.io",
    "threatfox": "ThreatFox",
}


@router.get("/settings/connectors")
async def list_connectors():
    catalog = get_connector_catalog()
    redis_ok = await redis_ping()
    ai_available = await ai.is_available()
    return {
        "connectors": [
            {
                **c,
                "label": _CONNECTOR_LABELS.get(c["name"], c["name"]),
                "key_url": _KEY_URLS.get(c["name"]),
            }
            for c in catalog
        ],
        "cache": {"redis": redis_ok},
        "ai": {
            "available": ai_available,
            "enabled": ai._ENABLED,
            "model": ai._MODEL,
            "endpoint": ai._OPENAI_URL or ai._OLLAMA_URL,
        },
    }
