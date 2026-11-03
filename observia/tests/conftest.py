import os

# Les tests d'intégration utilisent une base jetable : OBSERVIA_TEST_DSN (elle est réinitialisée).
TEST_DSN = os.environ.get("OBSERVIA_TEST_DSN")
if TEST_DSN:
    os.environ["OBSERVIA_DB_DSN"] = TEST_DSN
    os.environ.setdefault("OBSERVIA_POLICY_ENGINE", "local")
    os.environ["OBSERVIA_CONSOLE_JWT_SECRET"] = "test-secret-at-least-32-bytes-long!!"
    os.environ["OBSERVIA_LOKI_URL"] = ""
