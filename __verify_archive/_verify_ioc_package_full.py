import asyncio, zipfile, io
from export.ioc_package import generate_ioc_package

test_entities = [
    {'entity_type': 'IP_ADDRESS', 'canonical_value': '185.220.101.45', 'confidence': 0.94},
    {'entity_type': 'IP_ADDRESS', 'canonical_value': '2001:db8::1', 'confidence': 0.7},
    {'entity_type': 'DOMAIN', 'canonical_value': 'lockbit.onion', 'confidence': 0.88},
    {'entity_type': 'ONION_URL', 'canonical_value': 'http://lockbitxyzabc.onion', 'confidence': 0.91},
    {'entity_type': 'EMAIL_ADDRESS', 'canonical_value': 'actor@protonmail.com', 'confidence': 0.6},
    {'entity_type': 'FILE_HASH_SHA256', 'canonical_value': 'a' * 64, 'confidence': 0.90},
    {'entity_type': 'FILE_HASH_MD5', 'canonical_value': 'd41d8cd98f00b204e9800998ecf8427e', 'confidence': 0.85},
    {'entity_type': 'FILE_HASH_SHA1', 'canonical_value': 'da39a3ee5e6b4b0d3255bfef95601890afd80709', 'confidence': 0.85},
    {'entity_type': 'BITCOIN_ADDRESS', 'canonical_value': '1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2', 'confidence': 0.92},
    {'entity_type': 'ETHEREUM_ADDRESS', 'canonical_value': '0x742d35Cc6634C0532925a3b8D4C9C2C7f', 'confidence': 0.92},
    {'entity_type': 'MONERO_ADDRESS', 'canonical_value': '44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33', 'confidence': 0.92},
    {'entity_type': 'CVE_NUMBER', 'canonical_value': 'CVE-2023-12345', 'confidence': 0.9},
    {'entity_type': 'CVE_NUMBER', 'canonical_value': 'CVE-2024-9999', 'confidence': 0.9},
    {'entity_type': 'MITRE_TECHNIQUE', 'canonical_value': 'T1486', 'confidence': 0.95},
    {'entity_type': 'MALWARE_FAMILY', 'canonical_value': 'LockBit', 'confidence': 0.95},
    {'entity_type': 'AWS_ACCESS_KEY', 'canonical_value': 'AKIAIOSFODNN7EXAMPLE', 'confidence': 1.0},
    {'entity_type': 'GITHUB_TOKEN', 'canonical_value': 'ghp_1234567890abcdefghijklmnopqrstuvwxyz', 'confidence': 1.0},
    {'entity_type': 'JWT_TOKEN', 'canonical_value': 'eyJhbGc.eyJzdWI.SflKxw', 'confidence': 1.0},
    {'entity_type': 'URL', 'canonical_value': 'https://malicious.example.com/payload', 'confidence': 0.7},
]

test_investigation = {
    'id': 'test-123',
    'query': 'LockBit ransomware',
    'summary': 'LockBit ransomware infrastructure and actor chatter observed on multiple dark web forums.',
    'sources_used': {'tor': 'ok_5_pages', 'github': 'ok_3_results', 'otx': 'skipped_no_key'},
    'created_at': '2026-06-09T00:00:00Z',
}

async def test():
    zip_bytes = await generate_ioc_package(
        investigation_id='test-123',
        entities=test_entities,
        investigation=test_investigation,
        session=None,
    )

    zf = zipfile.ZipFile(io.BytesIO(zip_bytes))
    for name in [
        'README.md',
        'metadata.json',
        'iocs/hashes.txt',
        'iocs/ip_addresses.txt',
        'iocs/ipv6_addresses.txt',
        'iocs/crypto_wallets.txt',
        'iocs/credentials.txt',
        'iocs/cve_identifiers.txt',
        'iocs/mitre_techniques.txt',
        'iocs/domains.txt',
        'iocs/onion_urls.txt',
        'iocs/email_addresses.txt',
        'iocs/urls.txt',
        'detections/snort.rules',
        'detections/yara.yar',
        'detections/sigma.yml',
        'reports/entities.csv',
        'reports/summary.md',
    ]:
        content = zf.read(name).decode('utf-8')
        print(f'\n========== {name} ==========')
        print(content)

asyncio.run(test())
