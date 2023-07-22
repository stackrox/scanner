package java

import (
	"bytes"
	"fmt"
	"testing"
)

const testManifestMF = `
Manifest-Version: 1.0
Bundle-ManifestVersion: 2
Bundle-Name: tomcat-embed-core
Bundle-SymbolicName: org.apache.tomcat-embed-core
Bundle-Version: 10.1.8
Implementation-Title: Apache Tomcat
Implementation-Vendor: Apache Software Foundation
Implementation-Version: 10.1.8
Specification-Title: Apache Tomcat
Specification-Vendor: Apache Software Foundation
Specification-Version: 10.1
X-Compile-Source-JDK: 11
X-Compile-Target-JDK: 11

Name: jakarta/security/auth/message/
Implementation-Title: jakarta.security.auth.message
Implementation-Vendor: Apache Software Foundation
Implementation-Version: 3.0
Specification-Title: Jakarta Authentication SPI for Containers
Specification-Vendor: Eclipse Foundation
Specification-Version: 3.0

Name: jakarta/security/auth/message/callback/
Implementation-Title: jakarta.security.auth.message
Implementation-Vendor: Apache Software Foundation
Implementation-Version: 3.0
Specification-Title: Jakarta Authentication SPI for Containers
Specification-Vendor: Eclipse Foundation
Specification-Version: 3.0
`

func TestStopOnceFirstKeyIsFound(t *testing.T) {
	manifestBytes := bytes.NewBuffer([]byte(testManifestMF))
	manifest, err := parseManifestMFFromReader("", manifestBytes)
	if err != nil {
		panic(err)
	}

	fmt.Printf("%+v\n", manifest)
}
