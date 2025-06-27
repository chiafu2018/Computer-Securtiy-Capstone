# CSC 2025 Project3 - Ransomware Propagation and Payload

## 1. Prerequisites

### 1.1 Install Docker

Follow the instructions from [Install Docker Engine on Ubuntu](https://docs.docker.com/engine/install/ubuntu/)
to install docker on your machine.

### 1.2 Build Image

Run the following command to setup the image for development:

```bash
$ docker compose build
```

## 2. Run Containers

### 2.1 Bring up the Environment

Run the attacker and victim with

```bash
$ docker compose up -d
```

### 2.2 Attach to the Attacker

Attach to attacker container with:

```bash
docker exec -it attacker bash    
```

### 2.3 Attach to the Victim

Run the command to interact with victim

```bash
docker exec -it victim bash
```

### 2.4 Restart the Container

If the container exited after rebooting,
restart the container with

```bash
$ docker restart <container_name>
```

### 2.5 Stop and remove the containers
Remove the docker network and containers with

```
docker compose down
```

## 3. Remove the Images

Remove the docker image (csc2025-project3) with

```
docker rmi csc2025-project3
```

## 4. Build AES-Tool

Use the following command to build into executable:

```
$ gcc -o aes-tool aes-tool.c -lssl -lcrypto
```
