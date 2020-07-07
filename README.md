# cbsensor-linux-kmod

This project is a Linux kernel module used to detect and report security related events and take security related actions.

It is used by the VMware Carbon Black Endpoint Detection and Response product.

The distributions supported by this module are RedHat 6 and 7 and derivatives that use the same RedHat kernels (CentOS, Oracle Linux).

## Build from a Docker container

Start the Docker container
```bash
docker run -it --rm -v$PWD:/home/conan/project artifactory-pub.bit9.local:5000/cbr/cbr-linux-builder-kernel
```
From within the container:
```bash
cd /home/conan/project
mkdir build
cd build
conan install .. -j kernel-headers.json
cmake -DKERNELHEADERS_DIR=`jq -r .installed[0].packages[0].cpp_info.rootpath < kernel-headers.json`/kernel ../src/kmod
make
```

The `-j kernel-headers.json` argument exports information about the Conan package to a `.json` file. We use that file in the `cmake` command to get the full path to the kernel headers.

The kernel module, `cbsensor.ko` will be in the `build` directory.

## Running Gitlab-CI locally

Install the `gitlab-runner` Docker container for your OS.

To test run a kernel build run hen run:
```
gitlab-runner exec docker build-<version>
```
Where <version> is the kernel you wish to build, for example
```
gitlab-runner exec docker build-3.10.0-1062.el7.x86_64
```
