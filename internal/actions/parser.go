// Copyright 2025 The Aflock Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package actions

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// ActionType represents the type of a GitHub Action.
type ActionType int

const (
	ActionTypeJavaScript ActionType = iota
	ActionTypeDocker
	ActionTypeComposite
)

// String returns the action type name.
func (t ActionType) String() string {
	switch t {
	case ActionTypeJavaScript:
		return "javascript"
	case ActionTypeDocker:
		return "docker"
	case ActionTypeComposite:
		return "composite"
	default:
		return "unknown"
	}
}

// ActionMetadata holds parsed action.yml content.
type ActionMetadata struct {
	Name        string                  `yaml:"name"`
	Description string                  `yaml:"description"`
	Inputs      map[string]ActionInput  `yaml:"inputs"`
	Outputs     map[string]ActionOutput `yaml:"outputs"`
	Runs        ActionRuns              `yaml:"runs"`
}

// ActionInput describes a single action input.
type ActionInput struct {
	Description string `yaml:"description"`
	Required    bool   `yaml:"required"`
	Default     string `yaml:"default"`
}

// ActionOutput describes a single action output.
type ActionOutput struct {
	Description string `yaml:"description"`
	Value       string `yaml:"value"`
}

// ActionRuns describes how an action is executed.
type ActionRuns struct {
	Using      string            `yaml:"using"`
	Main       string            `yaml:"main"`
	Pre        string            `yaml:"pre"`
	PreIf      string            `yaml:"pre-if"`
	Post       string            `yaml:"post"`
	PostIf     string            `yaml:"post-if"`
	Image      string            `yaml:"image"`
	Env        map[string]string `yaml:"env"`
	Args       []string          `yaml:"args"`
	Entrypoint string            `yaml:"entrypoint"`
	Steps      []CompositeStep   `yaml:"steps"`
}

// CompositeStep represents a single step in a composite action.
type CompositeStep struct {
	ID               string            `yaml:"id"`
	Name             string            `yaml:"name"`
	If               string            `yaml:"if"`
	Uses             string            `yaml:"uses"`
	With             map[string]string `yaml:"with"`
	Run              string            `yaml:"run"`
	Shell            string            `yaml:"shell"`
	Env              map[string]string `yaml:"env"`
	WorkingDirectory string            `yaml:"working-directory"`
}

// Type returns the ActionType based on the runs.using field.
func (r *ActionRuns) Type() ActionType {
	using := strings.ToLower(r.Using)
	switch {
	case strings.HasPrefix(using, "node"):
		return ActionTypeJavaScript
	case using == "docker":
		return ActionTypeDocker
	case using == "composite":
		return ActionTypeComposite
	default:
		return ActionTypeJavaScript // Default to JS for unknown node versions
	}
}

// ParseActionYAML reads and parses action.yml or action.yaml from a directory.
func ParseActionYAML(dir string) (*ActionMetadata, error) {
	// Try action.yml first, then action.yaml
	for _, name := range []string{"action.yml", "action.yaml"} {
		path := filepath.Join(dir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("failed to read %s: %w", path, err)
		}

		var meta ActionMetadata
		if err := yaml.Unmarshal(data, &meta); err != nil {
			return nil, fmt.Errorf("failed to parse %s: %w", path, err)
		}
		return &meta, nil
	}

	return nil, fmt.Errorf("no action.yml or action.yaml found in %s", dir)
}
