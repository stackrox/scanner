package main

import (
	"fmt"
)

// ImageAndID encapsulates a name and id pair for a sample image
type ImageAndID struct {
	Name string
	ID   string
}

// FullName returns the name including the digest
func (i ImageAndID) FullName() string {
	return fmt.Sprintf("%s@%s", i.Name, i.ID)
}

var (
	// ImageNames lists the top images from DockerHub.
	ImageNames = []ImageAndID{
		{"openzipkin/zipkin", "sha256:651038f7a904bdcffb7176b4a4430e8c8fdc890326a7e4a470d388f8c6c755a1"},
		{"openzipkin/zipkin", "sha256:80c5aef490522ffd3f377fb670fdb153e0455d15e3031a3d605b3b03aaf95e04"},
		{"openzipkin/zipkin-dependencies", "sha256:f1039a688aee87557cda2de78364caeada41e4f6b851b2de13557f978d06fa69"},
		{"openzipkin/zipkin-dependencies", "sha256:fc5b2dd12516953391ca3a42dc53008ab4fe01be913432b1fad07d8579b8e964"},
		// Crash.
	}
)
