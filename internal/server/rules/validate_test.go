package rules

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/codingway-hub/a3/pkg/schema"
)

func TestValidateRule(t *testing.T) {
	validRule := Rule{
		ID: "custom.valid", Name: "合法规则", Category: "test",
		Target: TargetCommand, Patterns: []string{"curl\\s+.*evil"},
		Severity: schema.SeverityMedium, Action: schema.RiskActionAlert,
	}
	assert.NoError(t, Validate(validRule))

	// glob-only 规则合法
	globOnlyRule := validRule
	globOnlyRule.Patterns = nil
	globOnlyRule.Target = TargetPath
	globOnlyRule.PathGlobs = []string{"~/.ssh/*"}
	assert.NoError(t, Validate(globOnlyRule))

	invalidRules := []struct {
		label string
		rule  Rule
	}{
		{"空名称", func() Rule { r := validRule; r.Name = "  "; return r }()},
		{"非法 severity", func() Rule { r := validRule; r.Severity = schema.Severity("urgent"); return r }()},
		{"非法 action", func() Rule { r := validRule; r.Action = schema.RiskAction("warn"); return r }()},
		{"非法 target", func() Rule { r := validRule; r.Target = "everything"; return r }()},
		{"无任何模式", func() Rule { r := validRule; r.Patterns = nil; return r }()},
		{"非法正则", func() Rule { r := validRule; r.Patterns = []string{"([unclosed"}; return r }()},
	}
	for _, invalidCase := range invalidRules {
		assert.Error(t, Validate(invalidCase.rule), "%s 应被拒绝", invalidCase.label)
	}
}
