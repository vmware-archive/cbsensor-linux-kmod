# cbsensor-linux-kmod

This project is a Linux kernel module used to detect and report security related events and take security related actions.

It is used by the VMware Carbon Black Endpoint Detection and Response product.

The distributions supported by this module are RedHat 6 and 7 and derivatives that use the same RedHat kernels (CentOS, Oracle Linux).

Other distributions may work but have not been testing.

Specifically, this project is not likely to work with version 4+ kernels.

## Dependencies

Kernel source code must be installed

```
sudo yum install kernel-devel gcc-c++ make
```

### Special instructions for CMake for RHEL/CentOS 6/7 development machines:

This project depends on CMake version 3+
```
sudo yum install epel-release
sudo yum install cmake3
sudo yum remove cmake
sudo ln -s /usr/bin/cmake3 /usr/bin/cmake
sudo ln -s /usr/bin/cpack3 /usr/bin/cpack
sudo ln -s /usr/bin/ctest3 /usr/bin/ctest
```

## Building from source

Building is done using standard CMake commands

```bash
mkdir build
cd build
cmake ..
make
```
