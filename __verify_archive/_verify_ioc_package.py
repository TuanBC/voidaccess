import asyncio, zipfile, io, sys
from export.ioc_package import generate_ioc_package

test_entities = [
    {'entity_type': 'IP_ADDRESS',
     'canonical_value': '185.220.101.45',
     'confidence': 0.94},
    {'entity_type': 'DOMAIN',
     'canonical_value': 'lockbit.onion',
     'confidence': 0.88},
    {'entity_type': 'FILE_HASH_SHA256',
     'canonical_value': 'a' * 64,
     'confidence': 0.90},
    {'entity_type': 'MALWARE_FAMILY',
     'canonical_value': 'LockBit',
     'confidence': 0.95},
    {'entity_type': 'AWS_ACCESS_KEY',
     'canonical_value': 'AKIAIOSFODNN7EXAMPLE',
     'confidence': 1.0},
]

test_investigation = {
    'id': 'test-123',
    'query': 'LockBit ransomware',
    'summary': 'Test investigation summary',
    'sources_used': {'tor': 'ok_5_pages'},
    'created_at': '2026-06-09T00:00:00Z',
}

async def test():
    zip_bytes = await generate_ioc_package(
        investigation_id='test-123',
        entities=test_entities,
        investigation=test_investigation,
        session=None,
    )

    # Verify it's a valid ZIP
    zf = zipfile.ZipFile(io.BytesIO(zip_bytes))
    files = zf.namelist()
    print(f'ZIP contains {len(files)} files:')
    for f in sorted(files):
        size = zf.getinfo(f).file_size
        print(f'  {f} ({size} bytes)')

    # Verify credential redaction
    creds = zf.read('iocs/credentials.txt').decode('utf-8')
    assert 'AKIAIOSFODNN7EXAMPLE' not in creds, 'Credential not redacted!'
    assert 'AKIA' in creds, 'Credential prefix missing!'
    print('Credential redaction: OK')

    # Verify hashes file
    hashes = zf.read('iocs/hashes.txt').decode('utf-8')
    assert 'a' * 64 in hashes
    print('Hashes file: OK')

    # Verify YARA rules generated
    yara = zf.read('detections/yara.yar').decode('utf-8')
    assert 'rule VoidAccess_' in yara
    print('YARA rules: OK')

    # Verify Snort rules generated
    snort = zf.read('detections/snort.rules').decode('utf-8')
    assert '185.220.101.45' in snort
    print('Snort rules: OK')

    print(f'ZIP size: {len(zip_bytes)/1024:.1f}KB')

asyncio.run(test())
