On the main devenv machine do:
```bash
# Add Docker's official GPG key:
sudo apt-get update
sudo apt-get install ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc

# Add the repository to Apt sources:
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update
sudo apt-get install --assume-yes docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
```

Then do
```bash
# 1. Create the group if it doesn’t already exist (it should exist)
sudo groupadd docker

# 2. Add your user to it
sudo usermod -aG docker $USER

# 3. Log out and back in (or run `newgrp docker`) so the group change takes effect

sudo apt install make --assume-yes
git clone https://github.com/stacks-sbtc/sbtc.git
cd sbtc
git checkout  immunefi-sbtc-42752
docker compose -f docker/docker-compose.yml build sbtc-signer-1
docker compose -f docker/docker-compose.yml build sbtc-signer-2 sbtc-signer-3
docker compose -f docker/docker-compose.yml build emily-server
docker compose -f docker/docker-compose.yml build emily-aws-setup
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
make devenv-up
```

On the attacking servers do
```
sudo snap install --classic go

curl https://go.dev/dl/go1.24.2.linux-amd64.tar.gz

tar -C /usr/local -xzf go1.24.2.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
go version
```


```
go mod init sbtcattacklibp2p
go mod tidy
go build -o attacker1 attack_p2p_immunefi_42752_v1.go
go build -o attacker2 attack_p2p_immunefi_42752_v2.go
```