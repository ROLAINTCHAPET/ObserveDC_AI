"""Exécuteur d'actions : python -m executor.worker

V1.0 (mode ombre) : démarré avec EXECUTION_ENABLED=false, il ne fait rien.
V1.1 : couche fine (op_id, vérification post-action, journalisation) au-dessus
d'ansible-runner (décision D10), rollback (FR-19) et vérification (FR-20).
"""
import asyncio
import logging

from shared.config import get_settings

log = logging.getLogger("executor")


async def main() -> None:
    if not get_settings().execution_enabled:
        log.warning("exécution désactivée (mode ombre, V1.0) : aucune action ne sera exécutée")
        while True:
            await asyncio.sleep(3600)
    raise NotImplementedError("exécuteur Ansible : prévu en V1.1 (SPSD §4.6)")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(main())
