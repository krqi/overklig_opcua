# opcua Docker Build

Official docker container builds are available on [Docker Cloud](https://cloud.docker.com/u/opcua/repository/registry-1.docker.io/opcua/opcua)

The container includes the source code itself under `/opt/opcua` and prebuilt examples in `/opt/opcua/build/bin/examples/`.

You can use this container as a basis for your own application. 

Just starting the docker container will start the `server_ctt` example.

## Build locally

To build the container locally use:

```bash
git clone https://github.com/opcua/opcua
cd opcua
docker build -f tools/docker/Dockerfile .
```
