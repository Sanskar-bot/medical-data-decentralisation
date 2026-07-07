from pathlib import Path


def test_patient_dashboard_contains_new_structured_sections():
    template = Path('portals/templates/dashboard.html').read_text(encoding='utf-8')

    assert 'id="dashboard-hero"' in template
    assert 'id="health-snapshot"' in template
    assert 'id="medical-timeline"' in template
    assert 'id="quick-actions-grid"' in template
    assert 'id="security-details-card"' in template
    assert 'id="stat-audit"' in template
