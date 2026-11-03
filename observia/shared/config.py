"""Configuration par variables d'environnement (préfixe OBSERVIA_).

Les seuils chiffrés sont des valeurs de départ configurables (SPSD §0).
"""
from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

ROOT = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="OBSERVIA_", env_file=".env", extra="ignore")

    # Base de données : un DSN par rôle (feuille de route phase 4)
    db_dsn: str = "postgresql://observia:observia@localhost:5432/observia"
    db_reader_dsn: str | None = None  # lecture seule pour les outils MCP ; défaut = db_dsn
    db_ingest_dsn: str | None = None

    loki_url: str | None = None  # logs du datacenter (D5)

    # Garde-fou
    policy_engine: str = "opa"  # "opa" (D3) ou "local" (repli, tests)
    opa_url: str = "http://localhost:8181"
    opa_timeout_s: float = 0.5
    catalog_path: Path = ROOT.parent / "policies" / "catalog.yaml"
    shadow_mode: bool = True  # FR-18 : V1.0 démarre en mode ombre
    max_auto_actions_per_hour: int = 3  # BR-05
    max_impacted_equipment: int = 3  # BR-06
    min_confidence: float = 0.5  # UC-02 : confiance basse → niveau 3 forcé
    approval_ttl_s: int = 900  # FR-15 : délai d'expiration
    shadow_open_threshold: float = 0.95  # BR-09
    shadow_window_days: int = 28
    shadow_min_samples: int = 20

    # Pré-détection (document « Règles de pré-détection V1.0 »)
    storm_max_per_min: int = 10  # M7 : au-delà, regroupement en un incident « tempête »
    storm_quiet_s: int = 300  # tempête refermée après ce délai sans nouvelle alerte
    rule_eval_timeout_s: float = 20.0  # M10 : au-delà, TIMEOUT (jamais « normal »)
    rule_shadow_min_s: int = 86_400  # M14 : observation minimale avant promotion (sauf forçage motivé)
    internal_alert_interval_s: int = 900  # M10, M15 : une alerte interne par règle au plus tous les …

    # Agent (D2 rejouée, H1 invalidée : modèle local servi par Ollama, API compatible OpenAI)
    ollama_url: str = "http://localhost:11434"
    model_gateway_url: str = "http://localhost:11434/v1"
    model_name: str = "qwen2.5:7b-instruct"
    model_api_key: str | None = None
    model_temperature: float = 0.0  # décisions rejouables (NFR-12)
    model_timeout_s: float = 90.0  # inférence sur CPU : bien plus lente qu'une API cloud
    model_cost_per_mtok: float = 0.0  # NFR-15 : coût d'inférence mesuré par incident
    pseudonymize: bool = False  # utile seulement si les données quittent le site
    agent_max_steps: int = 8
    agent_max_seconds: float = 180.0  # SAD : 30 s visés ; à recalibrer au PoC modèle (§3.6)

    # RAG : runbooks et cas validés, plongements Ollama, recherche pgvector
    embed_model: str = "nomic-embed-text"
    embed_dim: int = 768  # doit correspondre à migrations/004 (vector(768))
    embed_doc_prefix: str = "search_document: "  # préfixes de tâche attendus par nomic-embed-text
    embed_query_prefix: str = "search_query: "
    knowledge_dir: Path = ROOT.parent / "knowledge" / "runbooks"
    rag_top_k: int = 4
    rag_min_score: float = 0.35
    rag_index_interval_s: int = 300
    agent_concurrency: int = 2
    mcp_url: str = "http://localhost:8001/mcp"
    mcp_token: str = "change-me-mcp-token"  # jeton de service ; valeur d'exemple refusée au démarrage

    # Exécuteur : désactivé jusqu'à la V1.1
    execution_enabled: bool = False

    # Notification (D11) : SMS + e-mail interne ; webhook d'équipe optionnel
    smtp_host: str | None = None
    smtp_port: int = 25
    smtp_from: str = "observia@localhost"
    email_recipients: str = ""  # liste séparée par des virgules
    sms_gateway_url: str | None = None
    sms_recipients: str = ""
    team_webhook_url: str | None = None
    console_base_url: str = "http://localhost:3000"

    # Console (NFR-04)
    console_jwt_secret: str | None = None  # HS256 pour le pilote
    oidc_jwks_url: str | None = None  # RS256 via SSO
    oidc_audience: str | None = None

    # Audit (D12)
    immudb_enabled: bool = False  # profil A− : PostgreSQL chaîné seul
    immudb_addr: str = "immudb:3322"
    immudb_user: str = "immudb"
    immudb_password: str = "immudb"

    @property
    def reader_dsn(self) -> str:
        return self.db_reader_dsn or self.db_dsn

    @property
    def ingest_dsn(self) -> str:
        return self.db_ingest_dsn or self.db_dsn


PLACEHOLDER_TOKEN = "change-me-mcp-token"


def require_service_token(settings: Settings) -> None:
    """Le jeton MCP protège l'accès aux outils : refus de démarrer avec la valeur d'exemple."""
    if settings.mcp_token == PLACEHOLDER_TOKEN or len(settings.mcp_token) < 24:
        raise SystemExit("OBSERVIA_MCP_TOKEN doit être défini (au moins 24 caractères) : voir deploy/gen-env.sh")


@lru_cache
def get_settings() -> Settings:
    return Settings()
