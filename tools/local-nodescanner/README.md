# Local Nodescanner
The local nodescanner is a tool to run the code related to Node Scanning locally without having to run the full Docker image or server.
Function-wise, it uses the very same calls and therefore is generating the same results a node scan running in the Node Scanner image would.

## Building
A `makefile` target named `local-nodescanner` is available in the main makefile.
It will create binaries in the projects' `bin` folder.
For ease of use, a Docker image is also available as target `local-nodescanner-image`.

## Running the Docker image
The Docker image only requires the path to a target filesystem to be scanned.
As the default for `fspath` is set to `/host`, one can run the image without changes when mounting the target fs to the right path:
`docker run -it -v /path/to/rhcos/fs:/host local-nodescanner:2.29.x-5-g7a3b50ef72-dirty`



## Requirements
The scanning code requires an `rpmdb` binary to be available in the executing systems `PATH`.
Be warned that RPM installed via `brew` on OSX *will not work correctly*.

The only required flag is the path to a filesystem. 
This can be a RO-mount of a running system (e.g. `/host` in the Compliance or Node-Scanner images),
or an unpacked filesystem, e.g. from a Docker image or ISO.

As of writing this readme, only RHCOS RPM components are supported by the Node Scan.
Therefore, not a full filesystem is needed. The minimal folder/file structure needed for a scan to succeed is:
- `/etc/redhat-release` with contents denoting an RHCOS system (e.g. `Red Hat Enterprise Linux CoreOS release 4.12`)
- `/usr/share/rpm` containing the RPM database

Additionally, for content sets to be discovered, a valid `/etc/os-release` must exist.
Example content:
```
NAME="Red Hat Enterprise Linux CoreOS"
VERSION="49.84.202212201621-0"
ID="rhcos"
ID_LIKE="rhel fedora"
VERSION_ID="4.9"
PLATFORM_ID="platform:el8"
PRETTY_NAME="Red Hat Enterprise Linux CoreOS 49.84.202212201621-0 (Ootpa)"
ANSI_COLOR="0;31"
CPE_NAME="cpe:/o:redhat:enterprise_linux:8::coreos"
HOME_URL="https://www.redhat.com/"
DOCUMENTATION_URL="https://docs.openshift.com/container-platform/4.9/"
BUG_REPORT_URL="https://bugzilla.redhat.com/"
REDHAT_BUGZILLA_PRODUCT="OpenShift Container Platform"
REDHAT_BUGZILLA_PRODUCT_VERSION="4.9"
REDHAT_SUPPORT_PRODUCT="OpenShift Container Platform"
REDHAT_SUPPORT_PRODUCT_VERSION="4.9"
OPENSHIFT_VERSION="4.9"
RHEL_VERSION="8.4"
OSTREE_VERSION='49.84.202212201621-0'
```