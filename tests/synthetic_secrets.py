"""Synthetic credential-format examples assembled at runtime; never use live credentials."""

# (rule, display shape, synthetic value). The shape is safe to publish; the value never is.
SECRETS = [
    ("SECRET-GITHUB", "ghp_ + 36 characters", "ghp_" + "Z8" * 18),
    ("SECRET-GITHUB", "github_pat_ + 82 characters", "github_pat_" + "Z8_" * 28),
    ("SECRET-AWS", "AKIA + 16 characters", "AKIA" + "Z8" * 8),
    ("SECRET-AI-API", "sk-proj- + 40 characters", "sk-proj-" + "Z8" * 20),
    ("SECRET-AI-API", "sk-ant-api03- + 40 characters", "sk-ant-api03-" + "Z8" * 20),
    ("SECRET-SLACK", "xoxb-<id>-<id>-<id>", "xoxb-" + "1234567890-" * 3),
    ("SECRET-NPM", "npm_ + 36 characters", "npm_" + "Z8" * 18),
    ("SECRET-GOOGLE", "AIza + 35 characters", "AIza" + "Z" * 35),
    ("SECRET-JWT", "eyJ<header>.<payload>.<signature>", "eyJ" + "Z" * 15 + "." + "Q" * 20 + "." + "X" * 20),
    ("SECRET-PRIVATE-KEY", "PEM private key header", "-----BEGIN " + "PRIVATE KEY-----"),
    ("SECRET-ASSIGNMENT", 'password = "<value>"', 'password = "' + "NotARealPassword-123" + '"'),
    ("SECRET-ASSIGNMENT", '"AZURE_CLIENT_SECRET": "<value>" in JSON', '{"env": {"AZURE_CLIENT_SECRET": "' + "Z8" * 20 + '"}}'),
    ("SECRET-ASSIGNMENT", "AccountKey=<value>; connection string", "AccountKey=" + "Z8" * 20 + ";"),
    ("SECRET-ASSIGNMENT", 'token = "<value>"', 'token = "' + "NotARealToken123" + '"'),
    ("SECRET-ASSIGNMENT", "SAS URL with sig=<value>", "https://example.com?sig=" + "Z8" * 20),
    ("SECRET-URL", "postgresql://user:<password>@host/db", "postgresql://test:" + "NotRealSecret" + "@example.com/db"),
    ("SECRET-AUTH-VALUE", "Authorization: Bearer <value>", "Authorization: Bearer " + "not-a-live-value-12345"),
]


def synthetic_secrets():
    return [(rule, value) for rule, _, value in SECRETS]
