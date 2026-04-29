import os
import time
import logging
import urllib.parse
import base64
from typing import Generator, Dict, Any, Optional
from adlfs import AzureBlobFileSystem
from azure.identity import ClientSecretCredential

try:
    import nilus
    from nilus import CustomSource
    NILUS_AVAILABLE = True
except ImportError:
    NILUS_AVAILABLE = False
    class CustomSource:
        def handles_incrementality(self) -> bool:
            return False
        def nilus_source(self, uri: str, table: str, **kwargs):
            pass

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

if NILUS_AVAILABLE:
    @nilus.source()
    def fraud_intelligence_source(uri: str, table: str, **kwargs):
        """Nilus source: parses URI and returns ServiceNow incidents resource."""

        logger.info("Nilus source: uri=%s ", uri)
        parsed = urllib.parse.urlparse(uri)
        qs = urllib.parse.parse_qs(parsed.query)

        tenant_id = (qs.get("client_id") or [""])[0].strip()
        client_id = (qs.get("client_id") or [""])[0].strip()
        storage_account = (qs.get("account") or [""])[0].strip()
        client_secret = (qs.get("secret") or [""])[0].strip()
        container = (qs.get("container") or [""])[0].strip()

        return fraud_intelligence_resource(
            tenant_id = tenant_id or None,
            client_id = client_id or None,
            client_secret = client_secret or None,
            storage_account = storage_account or None,
            container = container or None,
        )

if NILUS_AVAILABLE:
    @nilus.resource()
    def fraud_intelligence_resource(tenant_id: str = None,
        client_id: str = None,
        client_secret: str = None,
        storage_account: str = None,
        container: str = None,
    ):
        # Folder to read
        FOLDER = "aml"

        #Validation to check missing credentials
        if not tenant_id or not client_id or not client_secret or not storage_account or not container:
            missing = []
            if not client_id:
                missing.append("CLIENT_ID")
            if not client_secret:
                missing.append("CLIENT_SECRET")
            if not storage_account:
                missing.append("ACCOUNT")
            if not container:
                missing.append("CONTAINER")
            raise ValueError(
                "ABFSS credentials are missing. Set {} in the missing parameter"
                "and reference it in the workflow dataosSecrets. Currently missing: {}.".format(
                    ", ".join(missing), missing
                )
            )

        #Fetch source files from each entity's input folder to process folder
        return fetch_input_files_to_process(tenant_id, client_id,client_secret,storage_account,container)


    def fetch_input_files_to_process(tenant_id: str,
        client_id: str ,
        client_secret: str ,
        storage_account: str ,
        container: str ,
        ):

        # Create credential
        credential = ClientSecretCredential(
        tenant_id=tenant_id,
        client_id=client_id,
        client_secret=client_secret
        )
        # Connect to ABFSS
        fs = AzureBlobFileSystem(
            account_name=storage_account,
            credential=credential
        )

        FOLDER = "aml"

        # List CSV files
        folders = fs.ls(f"{container}/{FOLDER}")
        print(folders);

        entity_folder_names = []

        for path in folders:
            parts = path.split("/")        # split into ['raw','aml','sofl']
            new_path = "/".join(parts[1:]) # join ['aml','sofl'] → aml/sofl
            entity_folder_names.append(new_path)

        print(entity_folder_names)

        processed_files = []
        for entity_folder in entity_folder_names:

                # Read file content
                logger.info("Processing files for entity %s", entity_folder)

                logger.info("File processing from master folder")
                # Read master folder content
                master_input_path = f"abfss://{container}@{storage_account}.dfs.core.windows.net/{entity_folder}/master/input/"
                master_process_path = f"abfss://{container}@{storage_account}.dfs.core.windows.net/{entity_folder}/master/processed/"

                files = fs.ls(master_input_path)

                if files:
                    oldest_file = min(
                        (f for f in fs.ls(master_input_path) if fs.info(f)["type"] == "file"),
                        key=lambda f: fs.info(f)["last_modified"]
                    )
                    logger.info("Oldest File %s" , fs.info(oldest_file)["name"])

                    filename = oldest_file.split("/")[-1]

                    fs.copy(f"{master_input_path}{filename}",f"{master_process_path}{filename}")
                    fs.rm(f"{master_input_path}{filename}")
                    processed_files.append(f"{master_process_path}{filename}")

                else:
                    raise RuntimeError(
                            f"No files present in {master_input_path}"
                        )

                logger.info("File processing from transactional folder")
                # Read Transaction folder content
                transaction_input_path = f"abfss://{container}@{storage_account}.dfs.core.windows.net/{entity_folder}/transactional/input/"
                transaction_process_path = f"abfss://{container}@{storage_account}.dfs.core.windows.net/{entity_folder}/transactional/processed/"

                files = fs.ls(transaction_input_path)
                if files:
                    oldest_file = min(
                        (f for f in fs.ls(transaction_input_path) if fs.info(f)["type"] == "file"),
                        key=lambda f: fs.info(f)["last_modified"]
                    )
                    print(oldest_file);
                    print(fs.info(oldest_file)["name"]);
                    filename = oldest_file.split("/")[-1]

                    fs.copy(f"{transaction_input_path}{filename}",f"{transaction_process_path}{filename}")
                    fs.rm(f"{transaction_input_path}{filename}")
                    processed_files.append(f"{transaction_process_path}{filename}")

                else:
                    raise RuntimeError(
                            f"No files present in {master_input_path}"
                        )
        
        return processed_files

class GroupCompanyFraudulentDataSource(CustomSource):
    def handles_incrementality(self) -> bool:
        return False

    def nilus_source(self, uri: str, table: str, **kwargs):
        if NILUS_AVAILABLE:
            return fraud_intelligence_source(uri=uri, table=table, **kwargs)
        else:
            raise RuntimeError("Nilus not available")
