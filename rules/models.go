package rules

type Rules struct {
	Rules []Rule `yaml:"rules" json:"rules"`
}

type Rule struct {
	ID           string        `yaml:"id" json:"id"`
	Name         string        `yaml:"name" json:"name"`
	Severity     string        `yaml:"severity" json:"severity"`
	Description  string        `yaml:"description" json:"description"`
	Type         string        `yaml:"type" json:"type"`
	Check        Check         `yaml:"check" json:"check"`
	Remediation  string        `yaml:"remediation" json:"remediation"`
	Benchmarks   Benchmarks    `yaml:"benchmarks" json:"benchmarks"`
	ChaosTrigger *ChaosTrigger `yaml:"chaos_trigger" json:"chaos_trigger"`
}

type Benchmarks struct {
	CisControl     interface{} `yaml:"cis_control" json:"cis_control"`
	NISTCsf        string      `yaml:"nist_csf" json:"nist_csf"`
	MitreTechnique string      `yaml:"mitre_technique" json:"mitre_technique"`
}

type ChaosTrigger struct {
	Experiment string `yaml:"experiment" json:"experiment"`
	TargetType string `yaml:"target_type" json:"target_type"`
	Impact     string `yaml:"impact" json:"impact"`
}

type Check struct {
	Operator string      `yaml:"operator" json:"operator"`
	Value    interface{} `yaml:"value" json:"value"`
}