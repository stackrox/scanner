package fixtures

// GetLayerResponse is self explanatory
const GetLayerResponse = `{
  "Layer": {
    "Features": [
      {
        "Name": "pcre3",
        "Version": "2:8.35-3.3+deb8u4",
        "Vulnerabilities": [
          {
            "Name": "CVE-2017-16231",
            "Link": "https://security-tracker.debian.org/tracker/CVE-2017-16231"
          }
        ]
      }
    ]
  }
}`

// ErrorResponse is self explanatory
const ErrorResponse = `
{
  "Error": {
    "Message": "the resource cannot be found"
  }
}
`

// PostLayerResponse is self explanatory
const PostLayerResponse = `
{
	"Layer":{
		"Name":"sha256:sha",
		"Path": "http://registry/v2/library/nginx/blobs/layer",
		"Headers": {
			"Authorization": "Bearer thisisbearerauth"
		},
		"ParentName": "layer2",
		"Format": "Docker",
		"IndexedByVersion": 3
	}
}
`

// GetImageResponse is self explanatory
const GetImageResponse = `
{
	"Image": {
		"sha": "sha",
		"registry": "registry",
		"remote": "namespace/repo",
		"tag": "tag"
	}
}
`

// GetVulnDefsMetadata is includes last time vuln defs was updated.
const GetVulnDefsMetadata = `
{
	"lastUpdatedTime": "2020-12-08T19:05:20.491528869Z",
}
`
