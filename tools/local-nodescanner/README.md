# Local Nodescanner
The local nodescanner is a tool to run the code related to Node Scanning locally without having to run the full Docker image or server.
Function-wise, it uses the very same calls and therefore is generating the same results a node scan running in the Node Scanner image would.

## Building
A `makefile` target named `local-nodescanner` is available in the main makefile.
It will create binaries in the projects' `bin` folder.
For ease of use, a Docker image is also available as target `local-nodescanner-image`.

## Running the Docker image
As the default for `fspath` is set to `/host`, one can run the image without changes when mounting the target fs to the right path:
`docker run -it -v /path/to/rhcos/fs:/host local-nodescanner:$(make tag)`
Additional flags for the local nodescanner binary can be provided as args to the Docker image.
For example, to enable verbose output:
`docker run -it -v /path/to/rhcos/fs:/host local-nodescanner:$(make tag) --verbose`

## Requirements
The scanning code requires an `rpmdb` binary to be available in the executing systems `PATH`.
Be warned that RPM installed via `brew` on OSX *will not work correctly*, as it will produce an empty RPM database.

The only required flag is the path to a filesystem. 
This can be a RO-mount of a running system (e.g. `/host` in the Compliance or Node-Scanner images),
or an unpacked filesystem, e.g. from a Docker image or ISO.
Refer to `testdata/NodeScanning/rhcos4.12-minimal.tar.gz` for an archive containing a minimal example.
This archive can be used in conjunction with the Docker image:
```shell
tar xzf testdata/NodeScanning/rhcos4.12-minimal.tar.gz -C /tmp
make local-nodescanner-image
docker run -it -v /tmp/rhcos-412:/host local-nodescanner:$(make tag)
```
You should see a successful scan, indicated by the scanner noting that it found 503 installed RPM packages and 4 Content Sets.

The minimal folder/file structure needed for a scan to succeed is:
- `/etc/redhat-release` & `/etc/os-release` with contents denoting an RHCOS OS
- `/usr/share/rpm` containing the RPM database
- `/usr/share/buildinfo/content_manifest.json` containing the content sets