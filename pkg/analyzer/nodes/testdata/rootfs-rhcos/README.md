# ROOTFS-RHCOS

This directory structure mirrors what we have found in RHCOS 4.11.

* `usr/lib/system-release` contains the distro identification data.
* `etc/redhat-release` is a symlink to `/usr/lib/system-release`
    ```shell
    $ ls -l etc/redhat-release
    total 0
    lrwxr-xr-x  1 <OWNER>  <GROUP>  <DATE> redhat-release -> /usr/lib/system-release
    ```
