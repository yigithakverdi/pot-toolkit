import os
from pathlib import Path

## For allowing docker containers to own these below directories, to prevent
## future Permission Denied  problems on accessing these directores. 
DEFAULT_UID = 1000
DEFAULT_GID = 1000

## Base directories, these forms the base directories of the DPDK applications
## every component of the DPDK app and their configurations are stored under
## these directories as well as the packet processed data and logs are stored
## under these main directories
##
## Furthermore when generating config files or YAML files for firing up the DPDK
## application with the desired state and configs templates under the /template
## directory are used.
TEMPLATES_DIR = Path("./templates/")
HOST_ROOT_DIR = Path("/hostfs")
CONFIG_DIR = Path("/config")
DATA_DIR = Path("/data")

## Secrets and related files are joined with the data directory all the secrets lives 
## under the /data/secrets/ directory so when packets needs to be decrypted or encrypted
## information on the following directories are used
SECRETS_DIR = DATA_DIR.joinpath("secret")
SECRET_KEY_DIR = SECRETS_DIR.joinpath("keys")

## Compose and input config paths are stored under the following files, these are the
## files that are generated from the templates, different then the config directory
## they are used to fire up the DPDK application though they are in the form of ready
## generated YAML/config/JSON files.
CONFIG_FILE_PATH = "/compose/config.yaml"
INPUT_CONFIG_FILE_PATH = "/input/harbor.yaml"