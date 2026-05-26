# Docker

## Introduction and container forensics

Docker is a software platform that allows developers to create, test, and deploy applications quickly and easily using containers. It is a technology that has gained significant popularity in recent years, especially in the field of information technology.

Docker is used to encapsulate applications inside containers, meaning that each application runs in its own isolated environment. This allows developers to ensure that their applications behave consistently across different environments, regardless of hardware or software differences.

The main advantage of using Docker is the ability to create identical development and production environments, which helps guarantee the quality and consistency of applications. In addition, Docker enables continuous integration and continuous deployment, allowing developers to rapidly deploy new versions of their applications without interrupting the existing service.

Another advantage of Docker is that containers are extremely lightweight and fast to create. Containers can be started and stopped within seconds, allowing developers to test and debug applications much faster than in traditional environments.

However, there are also some disadvantages to using Docker. One of the main issues is the complexity of the platform. Docker can be difficult to learn and configure, especially for those without previous experience managing containers.

Another issue is that Docker can be slower than traditional environments in certain situations. Containers require an additional virtualization layer, which may impact performance in highly demanding environments.

Finally, another challenge when using Docker is that the technology is still evolving. As new features are added and existing capabilities are improved, it can be difficult to keep up with the changes.

## Objectives

- Learn how to perform basic operations with containers.
- Extract evidence from infrastructure systems that provide microservices through containers.

## Materials

- A Linux distribution with root or `sudo` access.
- **Docker CE** (Community Edition).
- Forensic and analysis utilities: **Docker Forensics Toolkit** (concepts from course readings), **Sysdig** (referenced in the syllabus), **container-diff**, **docker-explorer**, and **Docker Scout** (CLI plugin).

---

## Part A: Introduction to Docker

The following steps follow the lab sequence: install the engine, pull and run `nginx:latest`, inspect runtime objects, build a custom image from a Dockerfile, export artifacts, and clean up.

### 1. Install Docker

The official convenience script installs Docker CE and dependencies:

```bash
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
```

### 2. Display the installed version

Confirms client and server versions and API compatibility:

```bash
docker version
```

![alt text](./images/image.png)

### 3. Show host and daemon information

`docker info` reports storage driver, cgroup driver, registry mirrors, and whether the current user can talk to the daemon without `sudo`:

```bash
docker info
```

![alt text](./images/image-1.png)

### 4. Pull `nginx:latest` from Docker Hub

Downloads the image layers and metadata from the default registry:

```bash
docker pull nginx:latest
```

![alt text](./images/image-2.png)

### 5. List local images

```bash
docker image ls
```

![alt text](./images/image-3.png)

### 6. Run a container in detached mode

`-d` runs the process in the background; `--name` assigns a stable name for later `inspect`, `exec`, and forensic export:

```bash
docker run -d --name nginx-detached nginx:latest
```

![alt text](./images/image-4.png)

### 7. Run a container in interactive mode

`-it` allocates a TTY and keeps STDIN open—useful for manual inspection inside the guest filesystem:

```bash
docker run -it --name nginx-interactive nginx:latest /bin/bash
```

![alt text](./images/image-5.png)

Leave the interactive shell with `exit`.

### 8. List running containers

```bash
docker ps
```

![alt text](./images/image-6.png)

Only containers in the **running** state appear; stopped containers require `docker ps -a`.

### 9. Inspect container properties

`docker inspect` returns JSON with network settings, mount points, layer IDs, path to the container log, and runtime configuration—often the first structured artifact in a live triage:

```bash
docker inspect nginx-detached
```

![alt text](./images/image-7.png)

### 10. List Docker networks

Shows bridge, host, and custom networks used for container connectivity:

```bash
docker network ls
```

![alt text](./images/image-8.png)

### 11. Attach to a container console

`docker attach` connects the terminal to the container’s primary process (distinct from `exec`, which starts a new process):

```bash
docker attach nginx-detached
```

![alt text](./images/image-9.png)

### 12. Run an interactive shell inside a running container

```bash
docker exec -it nginx-detached /bin/bash
```

![alt text](./images/image-10.png)

`exec` is the usual way to examine a live filesystem without stopping the service.

### 13. Stop a container

```bash
docker stop nginx-detached
```

![alt text](./images/image-11.png)

### 14. Start a stopped container

```bash
docker start nginx-detached
```

![alt text](./images/image-12.png)

### 15. Remove a container

```bash
docker rm -f nginx-detached
```

![alt text](./images/image-13.png)

The `-f` flag forces removal even if the container is still running; otherwise you must `docker stop` it first.

### 16. Build an image from a Dockerfile

Example Dockerfile and helper script used in the lab:

```dockerfile
# Base image
FROM ubuntu

# Copy the file 'script' to the root directory of the container
COPY script /

# Give execute permissions to the file
RUN chmod +x /script
```

Build the image:

```bash
docker build -t myubuntu .
```

![alt text](./images/image-14.png)

Run a container from the new image:

```bash
docker run -d --name mycontainer myubuntu
```

![alt text](./images/image-15.png)

### 17. Commit a container to a new image

`docker commit` captures the writable layer of `mycontainer` as a new image tag (lab name `mydebian`, even though the base Dockerfile used Ubuntu):

```bash
docker commit mycontainer mydebian
```

![alt text](./images/image-16.png)

Verify the image is listed:

```bash
docker image ls
```

![alt text](./images/image-20.png)

### 18. Export an image to a tar archive

`docker save` preserves image layers and metadata for transfer to an analysis host:

```bash
docker save -o mydebian.tar mydebian
```

![alt text](./images/image-18.png)

```bash
ls mydebian.tar
```

![alt text](./images/image-19.png)

### 19. Export a container filesystem

`docker export` writes only the flattened container root filesystem (no image history or tags). In this step the `nginx-detached` container was exported as recorded in the lab:

```bash
docker export nginx-detached -o nginx-container.tar
```

![alt text](./images/image-21.png)

```bash
ls nginx-container.tar
```

![alt text](./images/image-22.png)

### 20. Remove the custom container

```bash
docker rm -f mycontainer
```

![alt text](./images/image-23.png)

### 21. Remove the committed image

```bash
docker image rm mydebian
```

![alt text](./images/image-24.png)

---

## Part B: Docker Forensics

### 1. Lessons from container incident response (Red Hat article)

Unlike virtual machines, Docker does not provide hypervisor-style snapshots that freeze disk and memory in one step. Acquisition therefore relies on a combination of techniques:

- **`docker commit`** — Persists the container writable layer as a new image. It captures filesystem changes but **not** running process state or RAM.
- **Host memory imaging (`dd`, AVML, or equivalent on the host)** — Required when volatile evidence (running processes, open connections, encryption keys) must be preserved; the container alone does not expose full memory through Docker CLI.
- **Ephemeral workloads** — Containers may be destroyed or recreated quickly, which narrows the window for live response and makes offline analysis of `/var/lib/docker` critical.

If indicators suggest **container escape** (for example the container was started with `--privileged`, sensitive `--mount` bindings, or `--pid=host`), the scope of the investigation should expand to the **host OS** and adjacent namespaces, not only the container filesystem.

### 2. Forensic use of `diff`, `save`, `export`, `load`, and `import`

| Command | Forensic role |
|--------|----------------|
| **`docker diff`** | Lists files added, changed, or deleted in the writable layer compared to the image. Useful for malware drops, persistence, and attacker modifications. |
| **`docker save`** | Archives a complete image (layers + metadata) to a tar file for transfer to an analysis workstation. |
| **`docker export`** | Exports the container root filesystem as a tar archive without image history—quick content copy for carving and file listing. |
| **`docker load`** | Restores an image previously written with `docker save` on another host for offline examination. |
| **`docker import`** | Creates a new image from an export tar (flattened filesystem), enabling analysis pipelines that expect an image tag. |

#### `docker diff`

```bash
docker diff nginx-detached
```

![alt text](./images/image-25.png)

#### `docker save`

```bash
docker save -o nginx-image.tar nginx:latest
```

![alt text](./images/image-26.png)

#### `docker export`

```bash
docker export nginx-detached -o nginx-container.tar
```

![alt text](./images/image-27.png)

#### `docker load`

```bash
docker load -i nginx-image.tar
```

![alt text](./images/image-28.png)

#### `docker import`

```bash
docker import nginx-container.tar imported-nginx
```

![alt text](./images/image-29.png)

Run a shell in the imported image:

```bash
docker run -it imported-nginx /bin/bash
```

![alt text](./images/image-30.png)

### 3. Image comparison with container-diff

[container-diff](https://github.com/GoogleContainerTools/container-diff) compares local images (and optionally remote registries) by layer, file, package, and history—useful for verifying whether a seized image matches a known baseline or for spotting unauthorized packages.

Install the binary:

```bash
wget https://github.com/GoogleContainerTools/container-diff/releases/download/v0.17.0/container-diff-linux-amd64 -O container-diff
chmod +x container-diff
sudo mv container-diff /usr/local/bin/
```

Verify installation:

```bash
container-diff version
```

![alt text](./images/image-31.png)

General image analysis:

```bash
container-diff analyze daemon://nginx:latest
```

![alt text](./images/image-32.png)

Filesystem contents:

```bash
container-diff analyze daemon://nginx:latest --type=file
```

![alt text](./images/image-33.png)

Installed packages (Debian/apt-based layers):

```bash
container-diff analyze daemon://nginx:latest --type=apt
```

![alt text](./images/image-34.png)

Image build history:

```bash
container-diff analyze daemon://nginx:latest --type=history
```

![alt text](./images/image-35.png)

Compare two local images (replace `<other-container>` with the second image name or ID):

```bash
container-diff diff daemon://nginx:latest daemon://<other-container>
```

![alt text](./images/image-36.png)

Filesystem differences:

```bash
container-diff diff daemon://nginx:latest daemon://<other-container> --type=file
```

![alt text](./images/image-37.png)

Package differences:

```bash
container-diff diff daemon://nginx:latest daemon://<other-container> --type=apt
```

![alt text](./images/image-38.png)

History differences:

```bash
container-diff diff daemon://nginx:latest daemon://<other-container> --type=history
```

![alt text](./images/image-39.png)

### 4. Offline analysis of a seized Docker logical image

#### a. Obtain and mount the forensic copy

Download the [provided logical image](https://drive.usercontent.google.com/download?id=1bFlnUBg1GH17h8pIQRywhDkHbNeTjvNZ&export=download&authuser=1) and place it so that the Docker data root is available under the path used below (in this lab, content was unpacked under `~/docker` with `/var/lib/docker` inside the image).

Install **docker-explorer** in a virtual environment:

```bash
python3 -m venv de-env
source de-env/bin/activate
pip install docker-explorer
```

#### b. Analyze Docker configuration and hosted containers

List all containers recorded in the image:

```bash
sudo de-env/bin/de.py -r /var/lib/docker list all_containers
```

![alt text](./images/image-40.png)

The JSON output was summarized as follows:

| Image | Container ID | Image ID | Start (UTC) | Mounts / volumes | Ports | Container log |
|-------|----------------|----------|-------------|------------------|-------|----------------|
| `homeassistant/home-assistant:latest` | `4ea041fd90ad…` | `306f9233e149…` | 2023-04-19T15:47:23Z | `ha_vol` → `/config` | 8123/tcp | `…/4ea041fd90ad…-json.log` |
| `nextcloud` | `5e38912f3093…` | `964325ce9b95…` | 2023-04-20T07:51:42Z | `nextcloud`, `config`, `apps` volumes → `/var/www/html` paths | 80/tcp | `…/5e38912f3093…-json.log` |
| `nginx:latest` | `e7cae6335bef…` | `6efc10a0510f…` | 2023-04-20T07:54:41Z | bind: `…/html` → `/usr/share/nginx/html` | 442/tcp, 80/tcp | `…/e7cae6335bef…-json.log` |

**Interpretation:** The host was running three distinct services—a **Home Assistant** automation stack (port **8123**), a **Nextcloud** collaboration instance with separate config and application volumes (port **80**), and an **nginx** reverse proxy or static site with a host directory bound into the web root (ports **80** and **442**). Mount points and log paths should be preserved in the chain of custody; container JSON logs under `/var/lib/docker/containers/<id>/` often contain stdout/stderr useful for timeline reconstruction.

#### c. Further reading

Additional walkthrough steps are described in [Container forensics with docker-explorer](https://osdfir.blogspot.com/2021/01/container-forensics-with-docker-explorer.html) (layer extraction, history, and deep filesystem views).

### 5. Docker Scout (image composition and CVE reporting)

[Docker Scout](https://www.docker.com/products/docker-scout/) analyzes image layers for packages and known vulnerabilities. While primarily a supply-chain tool, it supports forensic triage by quickly listing what software is present in an image under investigation.

Sign in to Docker Hub (required for some Scout features):

```bash
docker login
```

![alt text](./images/image-41.png)

Install the Scout CLI plugin:

```bash
curl -L https://github.com/docker/scout-cli/releases/download/v1.20.4/docker-scout_1.20.4_linux_amd64.tar.gz -o docker-scout.tar.gz

tar -xzf docker-scout.tar.gz

mkdir -p ~/.docker/cli-plugins

mv docker-scout ~/.docker/cli-plugins/docker-scout

chmod +x ~/.docker/cli-plugins/docker-scout
```

Verify installation:

```bash
docker scout version
```

![alt text](./images/image-42.png)

Summary view:

```bash
docker scout quickview nginx:latest
```

![alt text](./images/image-43.png)

CVE listing:

```bash
docker scout cves nginx:latest
```

![alt text](./images/image-44.png)

Remediation hints:

```bash
docker scout recommendations nginx:latest
```

![alt text](./images/image-45.png)

### 6. Docker checkpoints (forensic perspective)

From a forensic standpoint, **checkpoints** (when enabled) capture a container’s **running state**—memory and process context at a point in time—more completely than `docker commit`, which only records filesystem changes. They depend on **CRIU** (Checkpoint/Restore In Userspace) and experimental Docker features; they are not always available on default installations.

Relevant reading: [Analyzing Docker images for hunting secrets](https://tbhaxor.com/analyzing-docker-image-for-hunting-secrets/) (image-layer secrets and static analysis complements checkpoint-style live capture).

Install CRIU on the analysis host:

```bash
sudo apt install criu
```

Create a checkpoint of a running container:

```bash
docker checkpoint create nginx-detached checkpoint1
```

Resume from the checkpoint:

```bash
docker start --checkpoint checkpoint1 nginx-detached
```

Checkpoint data is stored on the host under:

```bash
ls /var/lib/docker/containers/<container_id>/checkpoints/
```

Preserve that directory with the same integrity controls as other `/var/lib/docker` evidence.
