import io
import re
import logging
import urllib.parse
from datetime import datetime
from typing import Optional

import pandas as pd
import nilus
from nilus import CustomSource
from adlfs import AzureBlobFileSystem
from azure.identity import ClientSecretCredential

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


# Root folder under the container that holds per-entity sub-folders.
ROOT_FOLDER = "aml"
SUB_FOLDERS = ("master", "transactional")


def sanitize_name(name: str) -> str:
    """Sanitize column / value tokens: drop extension, non-alphanum -> _, lowercase, strip _."""
    name = name.rsplit(".", 1)[0] if "." in name else name
    return re.sub(r"[^0-9a-zA-Z]+", "_", name).strip("_").lower()


def build_abfss_path(container: str, storage_account: str, *parts: str) -> str:
    """Build a fully qualified abfss:// URL with a trailing slash."""
    suffix = "/".join(p.strip("/") for p in parts if p)
    return f"abfss://{container}@{storage_account}.dfs.core.windows.net/{suffix}/"


def list_entity_folders(fs: AzureBlobFileSystem, container: str) -> list[str]:
    """List the entity sub-folders under <container>/<ROOT_FOLDER>/ as relative paths."""
    root = f"{container}/{ROOT_FOLDER}"
    try:
        entries = fs.ls(root)
    except Exception as e:
        logger.error(f"Cannot list {root}: {e}")
        return []

    entity_folders = []
    for path in entries:
        parts = path.split("/")
        rel = "/".join(parts[1:])  # drop the container name
        if rel:
            entity_folders.append(rel)
    logger.info(f"Discovered entity folders: {entity_folders}")
    return entity_folders


def move_oldest_file(
    fs: AzureBlobFileSystem,
    input_path: str,
    processed_path: str,
) -> Optional[str]:
    """Move the oldest file from input_path to processed_path. Return new path or None."""
    try:
        files = [f for f in fs.ls(input_path) if fs.info(f)["type"] == "file"]
    except FileNotFoundError:
        logger.warning(f"Input folder does not exist: {input_path}")
        return None

    if not files:
        logger.warning(f"No files present in {input_path}")
        return None

    oldest = min(files, key=lambda f: fs.info(f)["last_modified"])
    filename = oldest.split("/")[-1]
    src = f"{input_path}{filename}"
    dst = f"{processed_path}{filename}"

    try:
        fs.copy(src, dst)
        fs.rm(src)
        logger.info(f"Moved {src} -> {dst}")
        return dst
    except Exception as e:
        logger.error(f"Error moving {src} -> {dst}: {e}")
        return None


def load_csv_from_abfss(
    fs: AzureBlobFileSystem, abfss_path: str
) -> pd.DataFrame:
    """Download and parse a single CSV file (abfss path) into a DataFrame."""
    try:
        if not abfss_path.lower().endswith(".csv"):
            logger.warning(f"Skipping non-CSV file: {abfss_path}")
            return pd.DataFrame()

        with fs.open(abfss_path, "rb") as f:
            data = f.read()

        df = pd.read_csv(
            io.BytesIO(data),
            parse_dates=True,
            low_memory=False,
            keep_default_na=True,
            encoding="utf-8",
        )
        logger.info(f"Loaded {len(df)} rows from {abfss_path}")
        return df
    except Exception as e:
        logger.error(f"Error loading {abfss_path}: {e}")
        return pd.DataFrame()


@nilus.source
def fraud_intelligence_source(
    tenant_id: str,
    client_id: str,
    client_secret: str,
    storage_account: str,
    container: str,
    table: str,
):
    """
    Retrieves fraudulent CSV data from ABFSS (Azure Data Lake Gen2) and appends it to the
    specified table. For every entity folder under <container>/aml/, it picks the OLDEST
    file from {entity}/master/input/ and {entity}/transactional/input/, moves it to the
    matching .../processed/ folder, parses the CSV and yields its rows. Each yielded row is
    enriched with `entity`, `source_type` (master / transactional), `source_file` and
    `load_datetime` columns. All rows land in the single sink table given by `table`,
    matching the workflow YAML's `sink.options.dest-table`.

    Args:
        tenant_id (str): Azure AD tenant id of the Service Principal.
        client_id (str): Azure AD application (client) id of the Service Principal.
        client_secret (str): Service Principal client secret.
        storage_account (str): ADLS Gen2 storage account name (without suffix).
        container (str): Blob container that holds the `aml/` root folder.
        table (str): Destination table name (passed in from Nilus / sink dest-table).
    """
    if not table or not isinstance(table, str):
        raise ValueError("table must be a non-empty string")

    logger.info(
        f"Initializing ABFSS source for account={storage_account}, "
        f"container={container}, table={table} (client_secret=***)"
    )

    credential = ClientSecretCredential(
        tenant_id=tenant_id,
        client_id=client_id,
        client_secret=client_secret,
    )
    fs = AzureBlobFileSystem(
        account_name=storage_account,
        credential=credential,
    )

    def fraud_records():
        load_datetime = datetime.utcnow().isoformat() + "Z"

        entity_folders = list_entity_folders(fs, container)
        if not entity_folders:
            logger.warning(f"No entity folders found under {container}/{ROOT_FOLDER}")
            return

        total_rows = 0
        for entity_folder in entity_folders:
            entity_name = entity_folder.rstrip("/").split("/")[-1]
            logger.info(f"Processing files for entity {entity_name}")

            for sub in SUB_FOLDERS:
                input_path = build_abfss_path(
                    container, storage_account, entity_folder, sub, "input"
                )
                processed_path = build_abfss_path(
                    container, storage_account, entity_folder, sub, "processed"
                )

                logger.info(f"Processing {sub} folder for entity {entity_name}")
                processed_file = move_oldest_file(fs, input_path, processed_path)
                if not processed_file:
                    continue

                df = load_csv_from_abfss(fs, processed_file)
                if df.empty:
                    logger.warning(
                        f"No rows to yield from {processed_file} for entity {entity_name}"
                    )
                    continue

                for record in df.to_dict(orient="records"):
                    record["entity"] = entity_name
                    record["source_type"] = sub
                    record["source_file"] = processed_file
                    record["load_datetime"] = load_datetime
                    yield record

                total_rows += len(df)
                logger.info(
                    f"Yielded {len(df)} rows from {processed_file} into table {table}"
                )

        logger.info(f"Finished. Total rows yielded into {table}: {total_rows}")

    yield nilus.resource(
        fraud_records,
        name="fraud_intelligence",
        table_name=table,
        write_disposition="append",
    )


class GroupCompanyFraudulentDataSource(CustomSource):
    def handles_incrementality(self) -> bool:
        return False

    def nilus_source(self, uri: str, table: str, **kwargs):
        """Parse the custom:// URI and return the Nilus source."""
        redacted_uri = re.sub(r"secret=[^&]*", "secret=****", uri)
        logger.info(f"Received URI: {redacted_uri}")

        prefix = "custom://GroupCompanyFraudulentDataSource?"
        if not uri.startswith(prefix):
            raise ValueError(f"URI must start with '{prefix}'")

        query_string = uri[len(prefix):]
        query_params = urllib.parse.parse_qs(query_string, keep_blank_values=True)

        tenant_id = (query_params.get("tenant_id") or [""])[0].strip()
        client_id = (query_params.get("client_id") or [""])[0].strip()
        client_secret = (query_params.get("secret") or [""])[0].strip()
        storage_account = (query_params.get("account") or [""])[0].strip()
        container = (query_params.get("container") or [""])[0].strip()

        missing = []
        if not tenant_id:
            missing.append("tenant_id")
        if not client_id:
            missing.append("client_id")
        if not client_secret:
            missing.append("secret")
        if not storage_account:
            missing.append("account")
        if not container:
            missing.append("container")
        if missing:
            raise ValueError(
                "ABFSS credentials are missing. Set {} in dataosSecrets and "
                "reference them in the workflow URL. Currently missing: {}.".format(
                    ", ".join(missing), missing
                )
            )

        logger.info(
            f"Creating ABFSS source for table: {table} with container: {container}"
        )
        return fraud_intelligence_source(
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=client_secret,
            storage_account=storage_account,
            container=container,
            table=table,
        )
 