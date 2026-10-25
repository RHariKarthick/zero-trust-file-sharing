"""Single documented server startup: ``python -m server``."""

from __future__ import annotations

import logging
import ssl
import sys
import time

from database.core import initialize, transaction
from database.errors import DatabaseError
from database.files import list_storage_ids
from security.encryption import load_encryption_key
from security.errors import EncryptionError
from server.app import serve_forever
from server.bootstrap import create_first_admin
from server.config import load_server_config
from server.errors import ConfigurationError, StorageError
from server.storage import cleanup_orphans, initialize_storage
from server.tls import create_server_context


def main() -> None:
    """Initialize local dependencies and start the TLS listener fail-safely."""
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s", stream=sys.stderr)
    logger = logging.getLogger("server.startup")
    try:
        config = load_server_config()
        initialize()
        encryption_key = load_encryption_key(config.key_file)
        tls_context = create_server_context(config.tls_cert_file, config.tls_key_file, config.ca_cert_file)
        initialize_storage(config.storage_dir)
        with transaction() as conn:
            referenced_storage_ids = list_storage_ids(conn)
        cleanup_orphans(config.storage_dir, referenced_storage_ids, int(time.time()) - 3600)
        create_first_admin()
        serve_forever(config, tls_context, encryption_key)
    except KeyboardInterrupt:
        logger.info("Server stopped")
    except ConfigurationError as exc:
        logger.error("Server startup configuration failed: %s", exc)
        raise SystemExit(1) from None
    except DatabaseError:
        logger.error("Server startup failed while initializing local database state")
        raise SystemExit(1) from None
    except EncryptionError:
        logger.error("Server startup failed because the encryption key is missing or invalid")
        raise SystemExit(1) from None
    except StorageError:
        logger.error("Server startup failed while initializing local file storage")
        raise SystemExit(1) from None
    except ssl.SSLError:
        logger.error("Server startup failed because local TLS material is invalid")
        raise SystemExit(1) from None
    except Exception:
        # Unexpected exception details may contain private paths; keep stderr safe.
        logger.error("Server startup failed because of an unexpected local error")
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()

