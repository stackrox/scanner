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
Be warned that RPM installed via `brew` on OSX *will not work correctly*, as it will produce an empty RPM database.

The only required flag is the path to a filesystem. 
This can be a RO-mount of a running system (e.g. `/host` in the Compliance or Node-Scanner images),
or an unpacked filesystem, e.g. from a Docker image or ISO.
Refer to `testdata/NodeScanning/rhcos4.12-minimal.tar.gz` for an archive containing a minimal example.

The minimal folder/file structure needed for a scan to succeed is:
- `/etc/redhat-release` & `/etc/os-release` with contents denoting an RHCOS OS
- `/usr/share/rpm` containing the RPM database
- `/usr/share/buildinfo/content_manifest.json` containing the content sets