Steps to do the node scanning benchmark

Pre steps:

    1.Make sure docker is installed on your local laptop
    2.execute docker run -it --rm registry.access.redhat.com/ubi8/ubi
    3.make sure Vim, Python3, RPM and RPM-build are installed in the running ubi8 bash
        if not, do yum search <package name> and yum install <package name>

---------------------------------------------------------------------------------------------

    (optional) create a temporary/target folder in the running ubi8 bash for RPM specs. e.g mkdir temp-specs
    1.go to the target folder and create a python file to generate RPM specs e.g vim generate-junit-reports.sh (see the generate-junit-reports.sh in scanner/scripts folder)
        Modify the for loop in the python code for the number of specs you want to create
    2.execute the bash file e.g bash generate-rpm-specs.sh and you will be able to see the RPM spec files in the folder
    3.execute rpmbuild -bb *.spec to create RPM files based on all generated spec files
        You will see output like: Wrote: /root/rpmbuild/RPMS/x86_64/package_name9-0-0.x86_64.rpm Obviously this tells you where the rpm files are
    4.install all packages using the rpm files just created: yum localinstall <path to rpm files>/.*rpm  e.g yum localinstall /root/rpmbuild/RPMS/x86_64/.*rpm
    5.check the running ubi containers by executing: docker container ls and get the container id of the container where you are currently installing the rpm packages
    6.execute docker export [container id]>[tar name].tar (e.g docker export c8c57bb7e926>demoV1.tar) and unzip the tar ball to get the file system
    7.Go to github.com/stackrox/scanner/blob/master/benchmarks/analyzeNode folder and make sure to add local path to file system in line 13, then execute command: go test -bench=. -benchmem to run the test

