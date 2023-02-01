#this script is to generate simple RPM spec files
#spec => rpm files: run rpmbuild -bb *.spec
#install rpm: yum localinstall /root/rpmbuild/RPMS/x86_64/*.rpm

for x in range(100):
    with open("{}pkg.spec".format(x), "w") as f:
        f.write("Summary: Summary here\n")
        f.write("Name: package_name"+str(x)+"\n")
        f.write("Version: 0\n")
        f.write("Release: 0\n")
        f.write("License: Public\n")
        f.write("Group: Applications/System\n")
        f.write("Requires: bash\n")
        f.write("%description\n")
        f.write("Package description here\n")
        f.write("%files")
