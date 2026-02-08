#!/usr/bin/env bash
#
# Installs the TCP Learner and the Python environment needed to run the TCP Mapper

# SCRIPT_DIR should correspond to TCP-Fuzzer's root directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
readonly SCRIPT_DIR
readonly LEARNER_DIR=${SCRIPT_DIR}/learner
readonly MAPPER_DIR=${SCRIPT_DIR}/mapper
function install_learner() {
    echo "Installing Learner"
    (
        cd ${LEARNER_DIR}; 
        ./install.sh
    )
    
    if [[ $? -ne 0 ]]; then
        echo "Failed to install Learner"
        exit
    else 
        echo "Learner installed successfully"
    fi
}

function install_mapper_env() {
    echo "Installing Mapper environment"
    (
        cd ${MAPPER_DIR};
        ./install_env.sh
    )
    if [[ $? -ne 0 ]]; then
        echo "Failed to install Mapper environment"
        exit
    else 
        echo "Mapper environment installed successfully"
    fi
}

# Installing learner and mapper components
install_learner
install_mapper_env

