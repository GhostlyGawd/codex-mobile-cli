# Dependency report

Generated deterministically from `go.mod`/`go.sum`, Swift `Package.resolved`,
Terraform's dependency lockfile, the EnvBuilder source lock and patch, the
pinned official Codex CLI release assets, OCI references, and `.tool-versions`
by `python scripts/generate-supply-chain.py`. Run the generator after every
dependency or image change. This source report records declared inputs and
download pins; it does not prove which bytes are present in a built image. The
Syft SBOM captured from each exact built release image is authoritative for
installed binaries, transitive modules, and operating-system packages.

| Ecosystem | Dependency | Version | Relationship | Integrity/source |
| --- | --- | --- | --- | --- | --- |
| Build tool | `gitleaks` | `8.30.1` | direct | `.tool-versions` |
| Build tool | `go-licenses` | `2.0.1` | direct | `.tool-versions` |
| Build tool | `golang` | `1.26.5` | direct | `.tool-versions` |
| Build tool | `govulncheck` | `1.6.0` | direct | `.tool-versions` |
| Build tool | `python` | `3.12.10` | direct | `.tool-versions` |
| Build tool | `xcodegen` | `2.45.4` | direct | `.tool-versions` |
| Codex CLI application | `openai/codex` | `0.145.0` | direct | `https://github.com/openai/codex/releases/tag/rust-v0.145.0` |
| Codex CLI release asset | `codex-package-aarch64-unknown-linux-musl.tar.gz` | `0.145.0` | direct | SHA-256 `54f79a05aba6f9abf8ef988abcae8bf2fcefba20beb549b4ff2b3acdb2cb6f54` |
| Codex CLI release asset | `codex-package-x86_64-unknown-linux-musl.tar.gz` | `0.145.0` | direct | SHA-256 `71a28d362c96ac9829bf8203a2c71be451aeb726adb843167fdaf0eae8fe7dd9` |
| EnvBuilder derivative | `codex-mobile-envbuilder` | `1.3.0-codex-mobile.1` | direct | `infra/workspace/envbuilder/source-lock.json` |
| Go module | `cyphar.com/go-pathrs` | `v0.2.1` | transitive | SHA-256 `f67c75bce83056f5f598d0560eef77faf69c79e7696ec0eaa3e5ee0462f8d1bf` |
| Go module | `dario.cat/mergo` | `v1.0.0` | transitive | SHA-256 `00608dabd12fb23df598e80d3dc2f25dcfb83cd001b7dd39626baa3d86290569` |
| Go module | `github.com/anmitsu/go-shlex` | `v0.0.0-20200514113438-38f4b401e2be` | transitive | SHA-256 `f407938a53dc6408c214822672d15a3a39d321abe0f3bad6efcbd33e442a2c8f` |
| Go module | `github.com/armon/go-socks5` | `v0.0.0-20160902184237-e75332964ef5` | transitive | SHA-256 `d02c193596f1a7af521cf74f24037f859226d02e0e22d764942166311598a62a` |
| Go module | `github.com/bwesterb/go-ristretto` | `v1.2.3` | transitive | SHA-256 `d70e77b429068424397636dab77f8c1f404043929f81bb79e94650fc93339e0c` |
| Go module | `github.com/cloudflare/circl` | `v1.6.3` | transitive | SHA-256 `f463ce850185f4c09851e5f231896a4d1e9ae604eb811fdf04b5ef520b55720f` |
| Go module | `github.com/coder/websocket` | `v1.8.15` | direct | SHA-256 `e81d893de3869697dfd94cfabce107d55ce98b4894cf6d00fa53d584f1ed3540` |
| Go module | `github.com/cyphar/filepath-securejoin` | `v0.6.1` | transitive | SHA-256 `e42799d633d712262ddfe67aceaa6b4808125a28209a9572722bfcb328c8a551` |
| Go module | `github.com/davecgh/go-spew` | `v1.1.2-0.20180830191138-d8f796af33cc` | transitive | SHA-256 `53da8f488d8f216492d55c285d04fd0375b2f4c3375a0bea4b11567a7a8976e3` |
| Go module | `github.com/elazarl/goproxy` | `v1.7.2` | transitive | SHA-256 `636a3abab6fb12e95ed3d3e396141118db2a45f3e6608dca2902c5a42015dfea` |
| Go module | `github.com/emirpasic/gods` | `v1.18.1` | transitive | SHA-256 `157b621d828318a096d8acf064ac74882d0f426765a2b6207451bd8cf5c9d417` |
| Go module | `github.com/fxamacker/cbor/v2` | `v2.9.2` | transitive | SHA-256 `5f82ac9e8f7ec77733d1366febd79cd61c4fffeb729ae47c3d7409c83c1f87bf` |
| Go module | `github.com/gliderlabs/ssh` | `v0.3.8` | transitive | SHA-256 `6b86170f557bc4c17d8399d391d7e78dadd2c72d4f5430a3d5983859bf2f63a7` |
| Go module | `github.com/go-git/gcfg` | `v1.5.1-0.20230307220236-3a3c6141e376` | transitive | SHA-256 `fb3b3fb4f9a40e41f1dd4eba0c06f4950149ae94baef7d4e69ad768a473e0e22` |
| Go module | `github.com/go-git/go-billy/v5` | `v5.9.0` | transitive | SHA-256 `8c8b465eccd40d1b51fc095f7ab58f4cc3788f7f0143cf179d729b8a59a604f0` |
| Go module | `github.com/go-git/go-git-fixtures/v4` | `v4.3.2-0.20231010084843-55a94097c399` | transitive | SHA-256 `78c8dedf562095206a09d22a7612815bc96891a32b2f7b93929198944d8e393e` |
| Go module | `github.com/go-git/go-git/v5` | `v5.19.1` | direct | SHA-256 `9d7dbb027694e37fcae5b2a4b4ac2006647d95ac286157b50a4834ae0cf3374d` |
| Go module | `github.com/go-viper/mapstructure/v2` | `v2.5.0` | transitive | SHA-256 `bcce48268500cb777bcd1495b48c108018fb0625ad30f7e63c48005e7be3d51a` |
| Go module | `github.com/go-webauthn/webauthn` | `v0.17.4` | direct | SHA-256 `2854d2cf74764580e2527ff47038b75d326015e9d21bbe1e2934c796a5a19719` |
| Go module | `github.com/go-webauthn/x` | `v0.2.6` | transitive | SHA-256 `4c4c83b90008884818a71eb49ca8812485ffe674940bc2f135b1feb9fe54f6e9` |
| Go module | `github.com/golang-jwt/jwt/v5` | `v5.3.1` | transitive | SHA-256 `9187fcd434d615eeedfb556f2fb792fa32855566949caf5c075a9bc27eb76026` |
| Go module | `github.com/golang/groupcache` | `v0.0.0-20241129210726-2c02b8208cf8` | transitive | SHA-256 `7fea16b0c3a634f73c266107559232702ee10684311c7f6934a40e449368cec4` |
| Go module | `github.com/golang/protobuf` | `v1.5.4` | transitive | SHA-256 `8bb7892fca994e94845ce3d3c4d2a1012629327fbc7b943a01d9dd55ad5d59e9` |
| Go module | `github.com/google/go-cmp` | `v0.7.0` | transitive | SHA-256 `c24f37f36113b2fe0961467022c9fa6296225a206c60b489893b320726d5b8df` |
| Go module | `github.com/google/go-tpm` | `v0.9.8` | transitive | SHA-256 `b2502b011f45b7ed726d9bb4941c294a6a708515da6bce615ad3229ccc91016a` |
| Go module | `github.com/google/go-tpm-tools` | `v0.3.13-0.20230620182252-4639ecce2aba` | transitive | SHA-256 `a8910972e2f31f928347480a734cdc92d8a7e8a480c0befe8d628161c79d7537` |
| Go module | `github.com/google/uuid` | `v1.6.0` | transitive | SHA-256 `348bda24330eb231c0f27d630212d2833ac0cf2d4782bfa136b6f9edefbde05d` |
| Go module | `github.com/jackc/pgpassfile` | `v1.0.0` | transitive | SHA-256 `ffa1e6ab2d774acdb30aaeb655d346f2d335c1c867f338d218e049ea2729b083` |
| Go module | `github.com/jackc/pgservicefile` | `v0.0.0-20240606120523-5a60cdf6a761` | transitive | SHA-256 `882127a287bb525c0e418a4a16105a6cf322e1a3407e83833c414d8809c2971a` |
| Go module | `github.com/jackc/pgx/v5` | `v5.10.0` | direct | SHA-256 `5614af814da34a58bca3702a20439326beeb670004515a381385e147de197ebd` |
| Go module | `github.com/jackc/puddle/v2` | `v2.2.2` | transitive | SHA-256 `3d1f27c3e13fd70d062ee4454a68a2a18e94a28329e8a26fd3feb59c1ee2707a` |
| Go module | `github.com/jbenet/go-context` | `v0.0.0-20150711004518-d14ea06fba99` | transitive | SHA-256 `05048578f03545624e968707e85c72f0c9b00edfb25506142ca7cdd11a1337c0` |
| Go module | `github.com/kevinburke/ssh_config` | `v1.2.0` | transitive | SHA-256 `c79f381634c6c07cccc2f1f1d7c3d7c5b055cdf9f1a201da011794e207f5ddae` |
| Go module | `github.com/klauspost/cpuid/v2` | `v2.3.0` | transitive | SHA-256 `4b809130b9d852119e0c50ea906ae260a75fa059439ccb6a4e223fb05ce103d6` |
| Go module | `github.com/kr/pretty` | `v0.3.1` | transitive | SHA-256 `7e5443e0d3706005299298557351dcb6147828420527ae67f0cc39a9d467dcb1` |
| Go module | `github.com/kr/pty` | `v1.1.1` | transitive | SHA-256 `564a1723049ba01a6793df4efca15ab801082ee347bf90d514a64c04dfe0520c` |
| Go module | `github.com/kr/text` | `v0.2.0` | transitive | SHA-256 `e4dc7461ad19a98db2815dfae90cedbab1c8d7726af79029715689061a52f806` |
| Go module | `github.com/Microsoft/go-winio` | `v0.6.2` | transitive | SHA-256 `17655082d6bb79cc4660ef24dd9673dd14bc7d521757138d5543e5344468c9f6` |
| Go module | `github.com/onsi/gomega` | `v1.34.1` | transitive | SHA-256 `11430920a52333cb0a8d86edc5023d038cf6a3eaebbb19f336fa649ce5e27ba9` |
| Go module | `github.com/philhofer/fwd` | `v1.2.0` | transitive | SHA-256 `7ba0e705397bbc663e1b3df6dbf0122f81b2a7516ca5e32fc7544d0e84e866e3` |
| Go module | `github.com/pjbgf/sha1cd` | `v0.6.0` | transitive | SHA-256 `dd627c5b3f20bc3cf6f6ab97d4e7049a4025520f5d894e06c491eab34fd78b05` |
| Go module | `github.com/pkg/errors` | `v0.9.1` | transitive | SHA-256 `14404bc75cd2db5e28c298f2eeab017a2c5b51192e850030acae54c0b193c2de` |
| Go module | `github.com/pmezard/go-difflib` | `v1.0.1-0.20181226105442-5d4384ee4fb2` | transitive | SHA-256 `25a9af839a6c44871cb3b14635394844c913f3082da797825dd065aa16062fa5` |
| Go module | `github.com/ProtonMail/go-crypto` | `v1.1.6` | transitive | SHA-256 `65c57e468a70e909f4017f5bae540b0145dfa8b05cec197e7ff0e6371a4b7ddc` |
| Go module | `github.com/rogpeppe/go-internal` | `v1.14.1` | transitive | SHA-256 `5100781c63c1ea8b15d124132f299c0784e0bf25aee99ca589a5b4b48fe8b444` |
| Go module | `github.com/sergi/go-diff` | `v1.3.2-0.20230802210424-5b0b94c5c0d3` | transitive | SHA-256 `9faeb576bc9c385b8f2c237751cf2c07a07fb3a678b76c6f06053586d487baaf` |
| Go module | `github.com/sirupsen/logrus` | `v1.9.3` | transitive | SHA-256 `76e794409d42daaf6813717bc2f992180695b539948b345ebba7e337cbaacdb4` |
| Go module | `github.com/skeema/knownhosts` | `v1.3.1` | transitive | SHA-256 `5f6a2c43e4408caefab2109bbe11c71d59776658039bc6a91c41c5a918e7058f` |
| Go module | `github.com/stretchr/objx` | `v0.1.0` | transitive | SHA-256 `e06e2fd9d3b7559c22c46211a10e4b7dba32ea75210b26336aa9c800f3e162ce` |
| Go module | `github.com/stretchr/testify` | `v1.11.1` | transitive | SHA-256 `eecda2181ce9e44c11eff68866bf1aa39f9dadadf0890c8a8e316ebe054abbb5` |
| Go module | `github.com/tinylib/msgp` | `v1.6.4` | transitive | SHA-256 `98ec186f26032cf8f7e66900d818e361e8e0264f41b87c4376f4676fabf665c4` |
| Go module | `github.com/x448/float16` | `v0.8.4` | transitive | SHA-256 `a8bc08d48ef4f8d8d1154477cecd493d40a06825d2877496eb6b80293d664813` |
| Go module | `github.com/xanzy/ssh-agent` | `v0.3.3` | transitive | SHA-256 `fbfd79a497e0fd1b13c6a61c5fa7c7a8e5d9c3030ffb657261625e58cdaa4053` |
| Go module | `go.uber.org/mock` | `v0.6.0` | transitive | SHA-256 `87217d75f99b8085f911f39d6aca8bb160fac6aa4d6655db94b07f0db9f0bf76` |
| Go module | `golang.org/x/crypto` | `v0.53.0` | transitive | SHA-256 `419e0cba8f131d7e828b3376bcf3dde5f0461f2a20add2bd7c6e302cf154b2da` |
| Go module | `golang.org/x/exp` | `v0.0.0-20260410095643-746e56fc9e2f` | transitive | SHA-256 `5b717873ee8e2dce87da56fffcdd6ae16a49921cc908ae49ea4522d4d4d55df3` |
| Go module | `golang.org/x/mod` | `v0.37.0` | transitive | `https://golang.org/x/mod` |
| Go module | `golang.org/x/net` | `v0.56.0` | transitive | SHA-256 `470f23fe11731af2546703415e702d7f9b150d5b7eeb948ad82ec8c42c59b79a` |
| Go module | `golang.org/x/sync` | `v0.21.0` | transitive | SHA-256 `1cb208e314514ed091931629e0734517426cfce83aab68bef8a5db8348070b03` |
| Go module | `golang.org/x/sys` | `v0.47.0` | direct | SHA-256 `a3b5c63af6500800c1410e18ed536ad9d456411ec998e516f0ac71e19b0d816b` |
| Go module | `golang.org/x/term` | `v0.44.0` | transitive | SHA-256 `d2b2ef0d10ad363d20664c885e10b239bd8e0331212d5a9ce01fa1aec061ae67` |
| Go module | `golang.org/x/text` | `v0.39.0` | transitive | SHA-256 `51b673e292cebe7eb4d03e8e87a186108e950269ddac404bbfcffa0445f3caeb` |
| Go module | `golang.org/x/tools` | `v0.47.0` | transitive | `https://golang.org/x/tools` |
| Go module | `google.golang.org/protobuf` | `v1.33.0` | transitive | SHA-256 `b8d3b6aec00836afc9945a5275810a219d2e283fd1f5ca5dbf44feca81b01a62` |
| Go module | `gopkg.in/check.v1` | `v1.0.0-20201130134442-10cb98267c6c` | transitive | SHA-256 `1de8bfe000df756a8993564cc54369aa7b4dc1a59cba0ac18c088796aa918959` |
| Go module | `gopkg.in/warnings.v0` | `v0.1.2` | transitive | SHA-256 `c055d56c563c0d8e7fc4e7b510289674a0b3665c60b2171854d9011ecb4044c1` |
| Go module | `gopkg.in/yaml.v2` | `v2.4.0` | transitive | SHA-256 `0fcc60c04098ec262fc7e6369f8b01cfddc99fd251bf1762cb2a3c0937ee29a6` |
| Go module | `gopkg.in/yaml.v3` | `v3.0.1` | transitive | SHA-256 `7f1566fc6cc0cc45aa2c7baf72d23dd4a4bd8613669963a85aed174d8252ec20` |
| OCI image | `caddy` | `2.11.4-alpine` | direct | SHA-256 `5f5c8640aae01df9654968d946d8f1a56c497f1dd5c5cda4cf95ab7c14d58648` |
| OCI image | `docker.io/library/golang` | `1.26.5-bookworm` | direct | SHA-256 `1ecb7edf62a0408027bd5729dfd6b1b8766e578e8df93995b225dfd0944eb651` |
| OCI image | `docker.io/library/ubuntu` | `24.04` | direct | SHA-256 `4fbb8e6a8395de5a7550b33509421a2bafbc0aab6c06ba2cef9ebffbc7092d90` |
| OCI image | `ghcr.io/coder/coder` | `v2.34.6` | direct | SHA-256 `0ac9c07e9ff18ea9fecb07c08da838a032352e2b95c5fcd3bf279297cff1808a` |
| OCI image | `localhost/codex-mobile/control-plane` | `local-2026-07-15` | direct | `localhost/codex-mobile/control-plane:local-2026-07-15` |
| OCI image | `postgres` | `18.4-bookworm` | direct | SHA-256 `1961f96e6029a02c3812d7cb329a3b03a3ac2bb067058dec17b0f5596aca9296` |
| Operational tool | `syft` | `1.46.0` | direct | `.tool-versions` |
| Operational tool | `trivy` | `0.72.0` | direct | `.tool-versions` |
| Source archive | `github.com/coder/envbuilder` | `1.3.0` | direct | SHA-256 `f1c6334ee08736dec2585d96ad0afacc1888994bf2a2cdcf86e982b229fb8a85` |
| Source patch | `infra/workspace/envbuilder/envbuilder-v1.3.0-codex-mobile.patch` | `1.3.0-codex-mobile.1` | direct | SHA-256 `aea2941874a27d4deac96a0efe3a006ca6ea56d7cff982caa3a36877fc1756c3` |
| Swift package | `openapikit` | `3.9.0` | transitive | SHA-1 `343b2c1793058fcc53c1bd7e2907f8e3a4d640fb` |
| Swift package | `runestone` | `0.5.2` | direct | SHA-1 `592434a103a4d1ab83e14f87ac6eef569dd7a99d` |
| Swift package | `swift-algorithms` | `1.2.1` | transitive | SHA-1 `87e50f483c54e6efd60e885f7f5aa946cee68023` |
| Swift package | `swift-argument-parser` | `1.8.2` | transitive | SHA-1 `6a52f3251125d74daf04fcbd5e6f08a75d074382` |
| Swift package | `swift-collections` | `1.6.0` | transitive | SHA-1 `a0cb0954ecb21e4e31b0070e6ed5674e8556685a` |
| Swift package | `swift-docc-plugin` | `1.5.0` | transitive | SHA-1 `647c708be89f834fa6a6d4945442793a77ddf5b6` |
| Swift package | `swift-docc-symbolkit` | `1.0.0` | transitive | SHA-1 `b45d1f2ed151d057b54504d653e0da5552844e34` |
| Swift package | `swift-http-types` | `1.6.0` | transitive | SHA-1 `db774a277f60063a32d854f2980299caf06da041` |
| Swift package | `swift-numerics` | `1.1.1` | transitive | SHA-1 `0c0290ff6b24942dadb83a929ffaaa1481df04a2` |
| Swift package | `swift-openapi-generator` | `1.11.1` | direct | SHA-1 `73997cc62c2193d5046e431c9d546119dda14502` |
| Swift package | `swift-openapi-runtime` | `1.11.0` | direct | SHA-1 `f039fa6d6338aab5164f3d1be16281524c9a8f89` |
| Swift package | `swiftterm` | `1.14.0` | direct | SHA-1 `849e8a4f3d6f79ddee07152400137f1370c32621` |
| Swift package | `tree-sitter` | `0.20.9` | transitive | SHA-1 `98be227227af10cc7a269cb3ffb23686c0610b17` |
| Swift package | `treesitterlanguages` | `0.1.10` | direct | SHA-1 `15cf3a9ec3ab95e0d058b7df9f35619123c9e02d` |
| Swift package | `yams` | `6.2.2` | transitive | SHA-1 `a27b21e0c81c5bf42049b897a62aaf387e80f279` |
| Terraform provider | `registry.terraform.io/coder/coder` | `2.18.0` | direct | SHA-256 `de113a9629011b5144b7f77a411aa6e3e12c9ccb31ba9308f2881ff5ab4d1a46` |
| Terraform provider | `registry.terraform.io/kreuzwerker/docker` | `4.5.0` | direct | SHA-256 `7973ccc4d7198f3e600bb35cd6810f26576923a0796ed6ef95d8cb3a025035b2` |
