# ROOTFS-RHCOS-REL-SYMLINK

This directory structure mirrors what we have found in RHCOS 4.11
except it uses a symlink to a relative path.

* `release` contains the data.
* `etc/redhat-release` is a symlink to `release`
    ```shell
    $ ls -l etc/redhat-release
    total 0
    lrwxr-xr-x  1 <OWNER>  <GROUP>  <DATE> redhat-release -> ../release
    ```
