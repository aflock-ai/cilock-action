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

// Package platform provides CI platform detection and input parsing.
package platform

import "os"

// Platform represents a CI platform.
type Platform int

const (
	PlatformUnknown Platform = iota
	PlatformGitHub
	PlatformGitLab
	PlatformCLI
)

// String returns the platform name.
func (p Platform) String() string {
	switch p {
	case PlatformGitHub:
		return "github"
	case PlatformGitLab:
		return "gitlab"
	case PlatformCLI:
		return "cli"
	default:
		return "unknown"
	}
}

// Detect auto-detects the CI platform from environment variables.
func Detect() Platform {
	if os.Getenv("GITHUB_ACTIONS") == "true" {
		return PlatformGitHub
	}
	if os.Getenv("GITLAB_CI") == "true" {
		return PlatformGitLab
	}
	return PlatformCLI
}
