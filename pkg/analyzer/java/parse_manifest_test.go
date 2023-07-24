package java

import (
	"bytes"
	"github.com/stretchr/testify/assert"
	"testing"
)

const testTomcat10ManifestMF = `
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

const testTomcat9ManifestMF = `
Manifest-Version: 1.0
Automatic-Module-Name: org.apache.tomcat.embed.core
Bnd-LastModified: 1593547891735
Bundle-ManifestVersion: 2
Bundle-Name: tomcat-embed-core
Bundle-SymbolicName: org.apache.tomcat-embed-core
Bundle-Version: 9.0.37
Created-By: 1.8.0_252 (AdoptOpenJDK)
DSTAMP: 20200630
Implementation-Title: Apache Tomcat
Implementation-Vendor: Apache Software Foundation
Implementation-Version: 9.0.37
Private-Package: org.apache.naming.factory.webservices,org.apache.tomc
 at.util.bcel,org.apache.tomcat.util.http.fileupload.impl,org.apache.t
 omcat.util.http.fileupload.util.mime,org.apache.tomcat.util.json,org.
 apache.tomcat.util.modeler.modules,org.apache.tomcat.util.net.jsse,or
 g.apache.tomcat.util.threads.res
Provide-Capability: osgi.contract;osgi.contract=JavaJASPIC;version:Lis
 t<Version>="1.1,1";uses:="javax.security.auth.message,javax.security.
 auth.message.callback,javax.security.auth.message.config,javax.securi
 ty.auth.message.module",osgi.contract;osgi.contract=JavaServlet;versi
 on:List<Version>="4.0,3.1,3,2.5";uses:="javax.servlet,javax.servlet.a
 nnotation,javax.servlet.descriptor,javax.servlet.http,javax.servlet.r
 esources"
Require-Capability: osgi.contract;osgi.contract=JavaAnnotation;filter:
 ="(&(osgi.contract=JavaAnnotation)(version=1.3.0))",osgi.ee;filter:="
 (&(osgi.ee=JavaSE)(version=1.8))"
Specification-Title: Apache Tomcat
Specification-Vendor: Apache Software Foundation
Specification-Version: 9.0
TODAY: June 30 2020
Tool: Bnd-5.1.1.202006162103
TSTAMP: 2109
X-Compile-Source-JDK: 8
X-Compile-Target-JDK: 8

Name: javax/security/auth/message/
Implementation-Title: javax.security.auth.message
Implementation-Vendor: Apache Software Foundation
Implementation-Version: 1.1.FR
Specification-Title: Java Authentication SPI for Containers
Specification-Vendor: Sun Microsystems, Inc.
Specification-Version: 1.1

Name: javax/security/auth/message/callback/
Implementation-Title: javax.security.auth.message
Implementation-Vendor: Apache Software Foundation
Implementation-Version: 1.1.FR
Specification-Title: Java Authentication SPI for Containers
Specification-Vendor: Sun Microsystems, Inc.
Specification-Version: 1.1

Name: javax/security/auth/message/config/
Implementation-Title: javax.security.auth.message
Implementation-Vendor: Apache Software Foundation
Implementation-Version: 1.1.FR
Specification-Title: Java Authentication SPI for Containers
Specification-Vendor: Sun Microsystems, Inc.
Specification-Version: 1.1

Name: javax/security/auth/message/module/
Implementation-Title: javax.security.auth.message
Implementation-Vendor: Apache Software Foundation
Implementation-Version: 1.1.FR
Specification-Title: Java Authentication SPI for Containers
Specification-Vendor: Sun Microsystems, Inc.
Specification-Version: 1.1

Name: javax/servlet/
Implementation-Title: javax.servlet
Implementation-Vendor: Apache Software Foundation
Implementation-Version: 4.0.FR
Specification-Title: Java API for Servlets
Specification-Vendor: Sun Microsystems, Inc.
Specification-Version: 4.0

Name: javax/servlet/annotation/
Implementation-Title: javax.servlet
Implementation-Vendor: Apache Software Foundation
Implementation-Version: 4.0.FR
Specification-Title: Java API for Servlets
Specification-Vendor: Sun Microsystems, Inc.
Specification-Version: 4.0

Name: javax/servlet/descriptor/
Implementation-Title: javax.servlet
Implementation-Vendor: Apache Software Foundation
Implementation-Version: 4.0.FR
Specification-Title: Java API for Servlets
Specification-Vendor: Sun Microsystems, Inc.
Specification-Version: 4.0

Name: javax/servlet/http/
Implementation-Title: javax.servlet
Implementation-Vendor: Apache Software Foundation
Implementation-Version: 4.0.FR
Specification-Title: Java API for Servlets
Specification-Vendor: Sun Microsystems, Inc.
Specification-Version: 4.0

Name: javax/servlet/resources/
Implementation-Title: javax.servlet
Implementation-Vendor: Apache Software Foundation
Implementation-Version: 4.0.FR
Specification-Title: Java API for Servlets
Specification-Vendor: Sun Microsystems, Inc.
Specification-Version: 4.0
`

func TestStopOnceFirstKeyIsFound(t *testing.T) {
	manifest, err := parseManifestMFFromReader("", bytes.NewBufferString(testTomcat9ManifestMF))
	assert.NoError(t, err)
	assert.Equal(t, "9.0", manifest.specificationVersion)
	assert.Equal(t, "Apache Software Foundation", manifest.specificationVendor)
	assert.Equal(t, "9.0.37", manifest.implementationVersion)
	assert.Equal(t, "Apache Software Foundation", manifest.implementationVendor)
	assert.Equal(t, "", manifest.implementationVendorID)
	assert.Equal(t, "tomcat-embed-core", manifest.bundleName)
	assert.Equal(t, "org.apache.tomcat-embed-core", manifest.bundleSymbolicName)

	manifest, err = parseManifestMFFromReader("", bytes.NewBufferString(testTomcat10ManifestMF))
	assert.NoError(t, err)

	assert.Equal(t, "10.1", manifest.specificationVersion)
	assert.Equal(t, "Apache Software Foundation", manifest.specificationVendor)
	assert.Equal(t, "10.1.8", manifest.implementationVersion)
	assert.Equal(t, "Apache Software Foundation", manifest.implementationVendor)
	assert.Equal(t, "", manifest.implementationVendorID)
	assert.Equal(t, "tomcat-embed-core", manifest.bundleName)
	assert.Equal(t, "org.apache.tomcat-embed-core", manifest.bundleSymbolicName)
}
