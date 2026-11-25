content = open('tests/test_emr_api.py').read()
print('class TestReadAuditLogs count:', content.count('class TestReadAuditLogs:'))
print('DOC-AUDIT-REPORT count (non-2):', content.count('"DOC-AUDIT-REPORT"'))
print('DOC-AUDIT-REPORT2 count:', content.count('"DOC-AUDIT-REPORT2"'))
