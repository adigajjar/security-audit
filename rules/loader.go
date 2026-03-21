package rules

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

func LoadRuleFile(filePath string) (Rules, error) {
	file, err := os.ReadFile(filePath)
	if err != nil {
		return Rules{}, err
	}

	var rf Rules
	err = yaml.Unmarshal(file, &rf)
	if err != nil {
		return Rules{}, fmt.Errorf("failed to unmarshal yaml: %w", err)
	}

	fmt.Printf("Loaded %d rules from %s\n", len(rf.Rules), filePath)

	return rf, nil
}

func LoadRulesFromDirectory(dirPath string) (map[string]Rules, error) {
	allRules := make(map[string]Rules)

	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			subPath := filepath.Join(dirPath, entry.Name())
			subRules, err := LoadRulesFromDirectory(subPath)
			if err != nil {
				return nil, err
			}
			for k, v := range subRules {
				allRules[k] = v
			}
		} else if strings.HasSuffix(entry.Name(), ".yaml") || strings.HasSuffix(entry.Name(), ".yml") {
			fullPath := filepath.Join(dirPath, entry.Name())
			rules, err := LoadRuleFile(fullPath)
			if err != nil {
				return nil, err
			}
			key := strings.TrimSuffix(entry.Name(), filepath.Ext(entry.Name()))
			allRules[key] = rules
		}
	}

	return allRules, nil
}
