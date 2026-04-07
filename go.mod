module github.com/aflock-ai/cilock-action

go 1.26.0

require (
	dario.cat/mergo v1.0.2
	github.com/AlecAivazis/survey/v2 v2.3.7
	github.com/Masterminds/semver v1.5.0
	github.com/adrg/xdg v0.5.3
	github.com/aflock-ai/rookery/attestation v0.0.0
	github.com/aflock-ai/rookery/plugins/attestors/commandrun v0.0.0
	github.com/aflock-ai/rookery/plugins/attestors/git v0.0.0-00010101000000-000000000000
	github.com/aflock-ai/rookery/plugins/attestors/githubaction v0.0.0
	github.com/aflock-ai/rookery/plugins/attestors/material v0.0.0
	github.com/aflock-ai/rookery/plugins/attestors/product v0.0.0
	github.com/aflock-ai/rookery/plugins/signers/file v0.0.0
	github.com/aflock-ai/rookery/plugins/signers/fulcio v0.0.0
	github.com/aflock-ai/rookery/presets/cicd v0.0.0
	github.com/andreaskoch/go-fswatch v1.0.0
	github.com/aws/aws-sdk-go-v2 v1.41.3
	github.com/aws/aws-sdk-go-v2/config v1.32.11
	github.com/aws/aws-sdk-go-v2/credentials v1.19.11
	github.com/aws/aws-sdk-go-v2/feature/s3/manager v1.22.6
	github.com/aws/aws-sdk-go-v2/service/s3 v1.96.4
	github.com/containerd/errdefs v1.0.0
	github.com/creack/pty v1.1.24
	github.com/distribution/reference v0.6.0
	github.com/docker/cli v29.3.0+incompatible
	github.com/docker/docker v28.5.2+incompatible
	github.com/docker/go-connections v0.6.0
	github.com/go-chi/chi/v5 v5.2.5
	github.com/go-git/go-billy/v5 v5.8.0
	github.com/go-git/go-git/v5 v5.17.1
	github.com/golang-jwt/jwt/v5 v5.3.0
	github.com/google/uuid v1.6.0
	github.com/joho/godotenv v1.5.1
	github.com/julienschmidt/httprouter v1.3.0
	github.com/kballard/go-shellquote v0.0.0-20180428030007-95032a82bc51
	github.com/lib/pq v1.11.2
	github.com/mattn/go-isatty v0.0.20
	github.com/moby/go-archive v0.2.0
	github.com/moby/patternmatcher v0.6.0
	github.com/nektos/act v0.2.86
	github.com/opencontainers/image-spec v1.1.1
	github.com/opencontainers/selinux v1.13.1
	github.com/pkg/errors v0.9.1
	github.com/rhysd/actionlint v1.7.11
	github.com/sabhiram/go-gitignore v0.0.0-20210923224102-525f6e181f06
	github.com/sirupsen/logrus v1.9.4
	github.com/spf13/cobra v1.10.2
	github.com/spf13/pflag v1.0.10
	github.com/stretchr/testify v1.11.1
	github.com/testifysec/dropbox-clone v0.0.0-00010101000000-000000000000
	github.com/timshannon/bolthold v0.0.0-20240314194003-30aac6950928
	go.etcd.io/bbolt v1.4.3
	golang.org/x/crypto v0.48.0
	golang.org/x/term v0.40.0
	google.golang.org/protobuf v1.36.11
	gopkg.in/yaml.v3 v3.0.1
	gotest.tools/v3 v3.5.2
)

require (
	filippo.io/edwards25519 v1.1.1 // indirect
	github.com/BobuSumisu/aho-corasick v1.0.3 // indirect
	github.com/Masterminds/goutils v1.1.1 // indirect
	github.com/Masterminds/semver/v3 v3.4.0 // indirect
	github.com/Masterminds/sprig/v3 v3.3.0 // indirect
	github.com/Microsoft/go-winio v0.6.2 // indirect
	github.com/ProtonMail/go-crypto v1.1.6 // indirect
	github.com/STARRY-S/zip v0.2.3 // indirect
	github.com/aflock-ai/rookery/plugins/attestors/aws-codebuild v0.0.0-00010101000000-000000000000 // indirect
	github.com/aflock-ai/rookery/plugins/attestors/configuration v0.0.0-00010101000000-000000000000 // indirect
	github.com/aflock-ai/rookery/plugins/attestors/environment v0.0.0-00010101000000-000000000000 // indirect
	github.com/aflock-ai/rookery/plugins/attestors/github v0.0.0-00010101000000-000000000000 // indirect
	github.com/aflock-ai/rookery/plugins/attestors/gitlab v0.0.0-00010101000000-000000000000 // indirect
	github.com/aflock-ai/rookery/plugins/attestors/jenkins v0.0.0-00010101000000-000000000000 // indirect
	github.com/aflock-ai/rookery/plugins/attestors/jwt v0.0.0-00010101000000-000000000000 // indirect
	github.com/aflock-ai/rookery/plugins/attestors/oci v0.0.0-00010101000000-000000000000 // indirect
	github.com/aflock-ai/rookery/plugins/attestors/sarif v0.0.0 // indirect
	github.com/aflock-ai/rookery/plugins/attestors/secretscan v0.0.0 // indirect
	github.com/aflock-ai/rookery/plugins/attestors/slsa v0.0.0-00010101000000-000000000000 // indirect
	github.com/agnivade/levenshtein v1.2.1 // indirect
	github.com/andybalholm/brotli v1.2.0 // indirect
	github.com/apparentlymart/go-textseg/v15 v15.0.0 // indirect
	github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.7.6 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.18.19 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.4.19 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.7.19 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.8.5 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.4.20 // indirect
	github.com/aws/aws-sdk-go-v2/service/codebuild v1.68.9 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.6 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/checksum v1.9.11 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.13.19 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/s3shared v1.19.19 // indirect
	github.com/aws/aws-sdk-go-v2/service/signin v1.0.7 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.30.12 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.35.16 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.41.8 // indirect
	github.com/aws/smithy-go v1.24.2 // indirect
	github.com/aymanbagabas/go-osc52/v2 v2.0.1 // indirect
	github.com/bahlo/generic-list-go v0.2.0 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/bmatcuk/doublestar/v4 v4.10.0 // indirect
	github.com/bodgit/plumbing v1.3.0 // indirect
	github.com/bodgit/sevenzip v1.6.1 // indirect
	github.com/bodgit/windows v1.0.1 // indirect
	github.com/buger/jsonparser v1.1.2 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/charmbracelet/lipgloss v0.5.0 // indirect
	github.com/cloudflare/circl v1.6.3 // indirect
	github.com/containerd/errdefs/pkg v0.3.0 // indirect
	github.com/containerd/log v0.1.0 // indirect
	github.com/coreos/go-oidc/v3 v3.17.0 // indirect
	github.com/cpuguy83/go-md2man/v2 v2.0.7 // indirect
	github.com/cyphar/filepath-securejoin v0.5.1 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.0 // indirect
	github.com/digitorus/pkcs7 v0.0.0-20250730155240-ffadbf3f398c // indirect
	github.com/digitorus/timestamp v0.0.0-20250524132541-c45532741eea // indirect
	github.com/docker/docker-credential-helpers v0.9.3 // indirect
	github.com/docker/go-units v0.5.0 // indirect
	github.com/dsnet/compress v0.0.2-0.20230904184137-39efe44ab707 // indirect
	github.com/edwarnicke/gitoid v0.0.0-20220710194850-1be5bfda1f9d // indirect
	github.com/emirpasic/gods v1.18.1 // indirect
	github.com/fatih/color v1.18.0 // indirect
	github.com/fatih/semgroup v1.2.0 // indirect
	github.com/felixge/httpsnoop v1.0.4 // indirect
	github.com/fsnotify/fsnotify v1.9.0 // indirect
	github.com/fxamacker/cbor/v2 v2.9.0 // indirect
	github.com/gabriel-vasile/mimetype v1.4.13 // indirect
	github.com/gitleaks/go-gitdiff v0.9.1 // indirect
	github.com/go-git/gcfg v1.5.1-0.20230307220236-3a3c6141e376 // indirect
	github.com/go-jose/go-jose/v4 v4.1.3 // indirect
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-viper/mapstructure/v2 v2.4.0 // indirect
	github.com/gobwas/glob v0.2.3 // indirect
	github.com/goccy/go-json v0.10.5 // indirect
	github.com/golang/groupcache v0.0.0-20241129210726-2c02b8208cf8 // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/google/go-containerregistry v0.20.7 // indirect
	github.com/google/shlex v0.0.0-20191202100458-e7afc7fbc510 // indirect
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.27.4 // indirect
	github.com/h2non/filetype v1.1.3 // indirect
	github.com/hashicorp/go-version v1.7.0 // indirect
	github.com/hashicorp/golang-lru/v2 v2.0.7 // indirect
	github.com/huandu/xstrings v1.5.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/invopop/jsonschema v0.13.0 // indirect
	github.com/jbenet/go-context v0.0.0-20150711004518-d14ea06fba99 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/kevinburke/ssh_config v1.2.0 // indirect
	github.com/klauspost/compress v1.18.2 // indirect
	github.com/klauspost/pgzip v1.2.6 // indirect
	github.com/lestrrat-go/blackmagic v1.0.4 // indirect
	github.com/lestrrat-go/dsig v1.0.0 // indirect
	github.com/lestrrat-go/dsig-secp256k1 v1.0.0 // indirect
	github.com/lestrrat-go/httpcc v1.0.1 // indirect
	github.com/lestrrat-go/httprc/v3 v3.0.2 // indirect
	github.com/lestrrat-go/jwx/v3 v3.0.13 // indirect
	github.com/lestrrat-go/option/v2 v2.0.0 // indirect
	github.com/lucasb-eyer/go-colorful v1.2.0 // indirect
	github.com/mailru/easyjson v0.9.0 // indirect
	github.com/mattn/go-colorable v0.1.14 // indirect
	github.com/mattn/go-runewidth v0.0.17 // indirect
	github.com/mattn/go-shellwords v1.0.12 // indirect
	github.com/mgutz/ansi v0.0.0-20200706080929-d51e80ef957d // indirect
	github.com/mholt/archives v0.1.5 // indirect
	github.com/mikelolasagasti/xz v1.0.1 // indirect
	github.com/minio/minlz v1.0.1 // indirect
	github.com/mitchellh/copystructure v1.2.0 // indirect
	github.com/mitchellh/reflectwalk v1.0.2 // indirect
	github.com/moby/docker-image-spec v1.3.1 // indirect
	github.com/moby/moby/api v1.54.0 // indirect
	github.com/moby/moby/client v0.3.0 // indirect
	github.com/moby/sys/sequential v0.6.0 // indirect
	github.com/moby/sys/user v0.4.0 // indirect
	github.com/moby/sys/userns v0.1.0 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.3-0.20250322232337-35a7c28c31ee // indirect
	github.com/muesli/reflow v0.2.1-0.20210115123740-9e1d0d53df68 // indirect
	github.com/muesli/termenv v0.15.1 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/nwaples/rardecode/v2 v2.2.0 // indirect
	github.com/open-policy-agent/opa v1.13.1 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/owenrumney/go-sarif v1.1.1 // indirect
	github.com/pelletier/go-toml/v2 v2.2.4 // indirect
	github.com/pierrec/lz4/v4 v4.1.22 // indirect
	github.com/pjbgf/sha1cd v0.3.2 // indirect
	github.com/pkg/browser v0.0.0-20240102092130-5ac0b6a4141c // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/prometheus/client_golang v1.23.2 // indirect
	github.com/prometheus/client_model v0.6.2 // indirect
	github.com/prometheus/common v0.67.5 // indirect
	github.com/prometheus/procfs v0.17.0 // indirect
	github.com/rcrowley/go-metrics v0.0.0-20250401214520-65e299d6c5c9 // indirect
	github.com/rivo/uniseg v0.4.7 // indirect
	github.com/robfig/cron/v3 v3.0.1 // indirect
	github.com/rs/zerolog v1.33.0 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/sagikazarmark/locafero v0.11.0 // indirect
	github.com/secure-systems-lab/go-securesystemslib v0.9.1 // indirect
	github.com/segmentio/asm v1.2.1 // indirect
	github.com/sergi/go-diff v1.4.0 // indirect
	github.com/shopspring/decimal v1.4.0 // indirect
	github.com/sigstore/fulcio v1.8.5 // indirect
	github.com/sigstore/protobuf-specs v0.5.0 // indirect
	github.com/sigstore/sigstore v1.10.4 // indirect
	github.com/skeema/knownhosts v1.3.1 // indirect
	github.com/sorairolake/lzip-go v0.3.8 // indirect
	github.com/sourcegraph/conc v0.3.1-0.20240121214520-5f936abd7ae8 // indirect
	github.com/spf13/afero v1.15.0 // indirect
	github.com/spf13/cast v1.10.0 // indirect
	github.com/spf13/viper v1.21.0 // indirect
	github.com/stretchr/objx v0.5.2 // indirect
	github.com/subosito/gotenv v1.6.0 // indirect
	github.com/tchap/go-patricia/v2 v2.3.3 // indirect
	github.com/tetratelabs/wazero v1.9.0 // indirect
	github.com/ulikunitz/xz v0.5.15 // indirect
	github.com/valyala/fastjson v1.6.7 // indirect
	github.com/vektah/gqlparser/v2 v2.5.31 // indirect
	github.com/wasilibs/go-re2 v1.9.0 // indirect
	github.com/wasilibs/wazero-helpers v0.0.0-20240620070341-3dff1577cd52 // indirect
	github.com/wk8/go-ordered-map/v2 v2.1.8 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	github.com/xanzy/ssh-agent v0.3.3 // indirect
	github.com/xeipuuv/gojsonpointer v0.0.0-20190905194746-02993c407bfb // indirect
	github.com/xeipuuv/gojsonreference v0.0.0-20180127040603-bd5ef7bd5415 // indirect
	github.com/xeipuuv/gojsonschema v1.2.0 // indirect
	github.com/yashtewari/glob-intersection v0.2.0 // indirect
	github.com/zclconf/go-cty v1.14.4 // indirect
	github.com/zricethezav/gitleaks/v8 v8.30.0 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.64.0 // indirect
	go.opentelemetry.io/otel v1.42.0 // indirect
	go.opentelemetry.io/otel/metric v1.42.0 // indirect
	go.opentelemetry.io/otel/sdk v1.42.0 // indirect
	go.opentelemetry.io/otel/trace v1.42.0 // indirect
	go.step.sm/crypto v0.76.0 // indirect
	go.yaml.in/yaml/v2 v2.4.3 // indirect
	go.yaml.in/yaml/v3 v3.0.4 // indirect
	go.yaml.in/yaml/v4 v4.0.0-rc.3 // indirect
	go4.org v0.0.0-20230225012048-214862532bf5 // indirect
	golang.org/x/exp v0.0.0-20260209203927-2842357ff358 // indirect
	golang.org/x/mod v0.33.0 // indirect
	golang.org/x/net v0.50.0 // indirect
	golang.org/x/oauth2 v0.35.0 // indirect
	golang.org/x/sync v0.19.0 // indirect
	golang.org/x/sys v0.41.0 // indirect
	golang.org/x/text v0.34.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20260128011058-8636f8732409 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260203192932-546029d2fa20 // indirect
	google.golang.org/grpc v1.79.3 // indirect
	gopkg.in/go-jose/go-jose.v2 v2.6.3 // indirect
	gopkg.in/inf.v0 v0.9.1 // indirect
	gopkg.in/ini.v1 v1.67.1 // indirect
	gopkg.in/warnings.v0 v0.1.2 // indirect
	k8s.io/apimachinery v0.35.0 // indirect
	k8s.io/klog/v2 v2.130.1 // indirect
	k8s.io/kube-openapi v0.0.0-20250910181357-589584f1c912 // indirect
	k8s.io/utils v0.0.0-20251002143259-bc988d571ff4 // indirect
	sigs.k8s.io/json v0.0.0-20250730193827-2d320260d730 // indirect
	sigs.k8s.io/randfill v1.0.0 // indirect
	sigs.k8s.io/structured-merge-diff/v6 v6.3.0 // indirect
	sigs.k8s.io/yaml v1.6.0 // indirect
	tags.cncf.io/container-device-interface v1.1.0 // indirect
)

// Local development: point to local rookery checkout
replace github.com/aflock-ai/rookery/attestation => ../rookery/attestation

replace github.com/aflock-ai/rookery/plugins/attestors/commandrun => ../rookery/plugins/attestors/commandrun

replace github.com/aflock-ai/rookery/plugins/attestors/configuration => ../rookery/plugins/attestors/configuration

replace github.com/aflock-ai/rookery/plugins/attestors/environment => ../rookery/plugins/attestors/environment

replace github.com/aflock-ai/rookery/plugins/attestors/git => ../rookery/plugins/attestors/git

replace github.com/aflock-ai/rookery/plugins/attestors/github => ../rookery/plugins/attestors/github

replace github.com/aflock-ai/rookery/plugins/attestors/gitlab => ../rookery/plugins/attestors/gitlab

replace github.com/aflock-ai/rookery/plugins/attestors/githubaction => ../rookery/plugins/attestors/githubaction

replace github.com/aflock-ai/rookery/plugins/attestors/material => ../rookery/plugins/attestors/material

replace github.com/aflock-ai/rookery/plugins/attestors/product => ../rookery/plugins/attestors/product

replace github.com/aflock-ai/rookery/plugins/attestors/sarif => ../rookery/plugins/attestors/sarif

replace github.com/aflock-ai/rookery/plugins/attestors/secretscan => ../rookery/plugins/attestors/secretscan

replace github.com/aflock-ai/rookery/plugins/attestors/slsa => ../rookery/plugins/attestors/slsa

replace github.com/aflock-ai/rookery/plugins/attestors/jwt => ../rookery/plugins/attestors/jwt

replace github.com/aflock-ai/rookery/plugins/attestors/aws-codebuild => ../rookery/plugins/attestors/aws-codebuild

replace github.com/aflock-ai/rookery/plugins/attestors/jenkins => ../rookery/plugins/attestors/jenkins

replace github.com/aflock-ai/rookery/plugins/attestors/oci => ../rookery/plugins/attestors/oci

replace github.com/aflock-ai/rookery/plugins/signers/file => ../rookery/plugins/signers/file

replace github.com/aflock-ai/rookery/plugins/signers/fulcio => ../rookery/plugins/signers/fulcio

replace github.com/aflock-ai/rookery/presets/cicd => ../rookery/presets/cicd

replace github.com/testifysec/dropbox-clone => /tmp/dropbox-clone
