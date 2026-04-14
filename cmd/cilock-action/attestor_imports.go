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

package main

// Additional attestor plugins beyond the `presets/cicd` default set.
// These cover the full surface of a production CI/CD pipeline:
// build artifacts, container images, deploy manifests, vulnerability
// state, and policy verification.
import (
	_ "github.com/aflock-ai/rookery/plugins/attestors/docker"          // container build metadata
	_ "github.com/aflock-ai/rookery/plugins/attestors/k8smanifest"     // kubernetes deploy manifests
	_ "github.com/aflock-ai/rookery/plugins/attestors/lockfiles"       // package lockfile integrity
	_ "github.com/aflock-ai/rookery/plugins/attestors/oci"             // OCI image content
	_ "github.com/aflock-ai/rookery/plugins/attestors/policyverify"    // policy verification results
	_ "github.com/aflock-ai/rookery/plugins/attestors/sbom"            // software bill of materials
	_ "github.com/aflock-ai/rookery/plugins/attestors/system-packages" // OS package inventory
	_ "github.com/aflock-ai/rookery/plugins/attestors/vex"             // vulnerability exploit exchange
)
