MAPPER_SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
readonly MAPPER_SCRIPT_DIR
readonly ENV_DIR=${MAPPER_SCRIPT_DIR}/.venv

# Installing dependencies
echo "Installing dependencies where necessary."
sudo apt-get update
sudo apt-get install -y libcap-dev tcpdump
dpkg -s libcap-dev >/dev/null 2>&1 || echo "Failed to install libcap-dev"; exit 1

if [[ -d ${ENV_DIR} ]]
then
    echo "Detected Python virtual environment. Skipping Python environment creation."
else
    echo "Creating a Python virtual environment at $ENV_DIR"
    python3 -m venv $ENV_DIR
    source $ENV_DIR/bin/activate
    echo "Installing required libraries"
    pip install --upgrade pip
    pip install -r ${MAPPER_SCRIPT_DIR}/requirements.txt
    python -c "import scapy.all" || echo "Failed to install Scapy"; exit 1
fi

# If the script is being sourced, activate the environment
if [[ "${BASH_SOURCE[0]}" != "$0" ]]; then
    echo "Activating Mapper virtual environment at ${MAPPER_ENV_DIR}"
    source ${ENV_DIR}/bin/activate
else
    echo "Before running the Mapper, do not forget to activate environment by running:"
    echo "> source ${ENV_DIR}/bin/activate"
fi