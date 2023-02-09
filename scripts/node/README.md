# Steps to benchmark node scanning 

## Pre steps:

quay.io/repository/rhacs-eng/sandbox:benchmark-node-analyze-1.0 is an Ubi8 based image with vim, RPM and RPM-build installed. Those packages are necessary for benchmark node analyze function

back-up image: `quay.io/rh_ee_yli3/nodes:benchmark-node-analyze-1.1`

execute
```
docker run -it --rm quay.io/repository/rhacs-eng/sandbox:benchmark-node-analyze-1.1
```
---------------------------------------------------------------------------------------------

1.In the running ubi8 container, go to the `/tmp-specs` folder and make sure `generate-rpm-specs.sh` is there (check dockerfile line 6)

2.execute the bash file: bash generate-rpm-specs.sh <number of the RPM specs>  . You will be able to see the RPM spec files in the folder
```
bash generate-rpm-specs.sh 100
```
3.execute
```
rpmbuild -bb *.spec
```
You will see output like: `Wrote: /root/rpmbuild/RPMS/x86_64/package_name9-0-0.x86_64.rpm` This gives you the path where RPM files were generated to.

4.install all packages using the rpm files just created: yum localinstall <path to rpm files>/.*rpm  
```
yum localinstall /root/rpmbuild/RPMS/x86_64/.*rpm
```
5.check the running ubi containers by executing: `docker container ls` and get the container id of the container where you are currently installing the rpm packages

6.execute `docker export [container id]>[tar name].tar` (e.g `docker export c8c57bb7e926>demoV1.tar`) and unzip the tar ball to get the file system

7.Go to **scanner/benchmarks/analyzeNode** folder and make sure to add local path to file system in line 13, then execute command:
```
go test -bench=. -benchmem
```
