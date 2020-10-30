package k8sloader

type KubernetesCVEFeedYAML struct {
	CVE         string                     `json:"cve"`
	URL         string                     `json:"url"`
	IssueURL    string                     `json:"issueUrl"`
	Description string                     `json:"description"`
	Components  []string                   `json:"components"`
	CVSS        *KubernetesCVEFeedYAMLCVSS `json:"cvss"`
	Affected    []string                   `json:"affected"`
	FixedIn     []string                   `json:"fixedIn"`
}

type KubernetesCVEFeedYAMLCVSS struct {
	NVD        *KubernetesCVEFeedYAMLNVDCVSS        `json:"nvd"`
	Kubernetes *KubernetesCVEFeedYAMLKubernetesCVSS `json:"kubernetes"`
}

type KubernetesCVEFeedYAMLNVDCVSS struct {
	ScoreV2  float64 `json:"scoreV2"`
	VectorV2 string  `json:"vectorV2"`
	ScoreV3  float64 `json:"scoreV3"`
	VectorV3 string  `json:"vectorV3"`
}

type KubernetesCVEFeedYAMLKubernetesCVSS struct {
	ScoreV3  float64 `json:"scoreV3"`
	VectorV3 string  `json:"vectorV3"`
}
