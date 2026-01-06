#!/usr/bin/env bash
set -e

source /etc/os-release
if [[ "$VERSION_ID" != "24.04" ]] || [[ "$ID" != "ubuntu" ]]; then
    echo "Error: This script requires Ubuntu 24.04 (detected: $ID $VERSION_ID)"
    exit 1
fi

script_dir=$(dirname "$0")
cd "$script_dir/.."

echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu noble main' | \
    sudo tee /etc/apt/sources.list.d/intel-sgx.list

wget -qO - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | \
    sudo gpg --dearmor -o /usr/share/keyrings/intel-sgx-archive-keyring.gpg

echo 'deb [arch=amd64 signed-by=/usr/share/keyrings/intel-sgx-archive-keyring.gpg] https://download.01.org/intel-sgx/sgx_repo/ubuntu noble main' | \
    sudo tee /etc/apt/sources.list.d/intel-sgx.list

sudo apt-get update
sudo apt-get install -y \
    libsgx-launch \
    libsgx-urts \
    libsgx-epid \
    libsgx-quote-ex \
    libsgx-dcap-ql \
    libsgx-dcap-default-qpl \
    libsgx-dcap-quote-verify \
    libsgx-ae-qe3 \
    libsgx-ae-qve \
    sgx-aesm-service

sudo systemctl start aesmd
sudo systemctl enable aesmd
#sudo systemctl status aesmd

# Note. Better edit sgx_default_qcnl.conf instead of replacing
tee /etc/sgx_default_qcnl.conf << EOF
{
    "pccs_url": "https://api.trustedservices.intel.com/sgx/certification/v4/",
    "use_secure_cert": true,
    "collateral_service": "https://api.trustedservices.intel.com/sgx/cerTification/v4/",
    "retry_times": 6,
    "retry_delay": 10
}
EOF

docker run -d --rm \
    --device /dev/sgx_enclave \
    --device /dev/sgx_provision \
    -v /var/run/aesmd/aesm.socket:/var/run/aesmd/aesm.socket \
    -v $HOME/.cache/rs_amadeusd:/rs_amadeusd \
    -v $(pwd):/node \
    -w /node \
    -p 36969:36969/udp \
    -p 3000:3000/tcp \
    -e RUST_LOG=info \
    -e WORKFOLDER=/rs_amadeusd \
    -e UDP_ADDR=0.0.0.0:36969 \
    -e HTTP_PORT=3000 \
    --name amadeus-gramine \
    --entrypoint /bin/bash \
    gramineproject/gramine \
    -c "./scripts/setup-tee.sh && gramine-sgx amadeusd"

#docker run -it --rm \
#    --device /dev/sgx_enclave \
#    --device /dev/sgx_provision \
#    -v /var/run/aesmd/aesm.socket:/var/run/aesmd/aesm.socket \
#    -v $HOME/.cache/rs_amadeusd:/rs_amadeusd \
#    -v $(pwd):/node \
#    -w /node \
#    -p 36969:36969/udp \
#    -p 3000:3000/tcp \
#    -e RUST_LOG=info \
#    -e WORKFOLDER=/rs_amadeusd \
#    -e UDP_ADDR=0.0.0.0:36969 \
#    -e HTTP_PORT=3000 \
#    --name amadeus-gramine \
#    gramineproject/gramine \
#    bash
