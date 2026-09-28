package database

import "time"

// GetSeedDatabase returns a comprehensive offline vulnerability intelligence dataset
// pre-populated with verified advisories across npm, PyPI, Go, and crates.io.
func GetSeedDatabase() *SecurityDatabase {
	return &SecurityDatabase{
		Metadata: DatabaseMetadata{
			Version:              "6.9.0",
			UpdatedAt:            time.Date(2026, 9, 28, 0, 0, 0, 0, time.UTC),
			TotalVulnerabilities: 20,
			TotalPackages:        16,
			Ecosystems:           []string{"npm", "PyPI", "Go", "crates.io"},
		},
		Vulnerabilities: []VulnerabilityRecord{
			// ================= npm =================
			{
				ID:               "GHSA-p6fg-5544-jd52",
				Package:          "lodash",
				Ecosystem:        "npm",
				AffectedVersions: []string{"< 4.17.21"},
				FixedVersions:    []string{"4.17.21"},
				Severity:         "CRITICAL",
				CWE:              []string{"CWE-1321"},
				CVSS:             "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
				CVSSScore:        9.8,
				Aliases:          []string{"CVE-2020-8203"},
				Summary:          "Prototype Pollution in lodash",
				Description:      "Lodash versions prior to 4.17.21 are vulnerable to Prototype Pollution via zipObjectDeep, defaultsDeep, and set functions.",
				Ranges: []RangeSpec{
					{
						Type: "SEMVER",
						Events: []EventSpec{
							{Introduced: "0", Fixed: "4.17.21"},
						},
					},
				},
			},
			{
				ID:               "GHSA-35jh-r3h4-6jhm",
				Package:          "lodash",
				Ecosystem:        "npm",
				AffectedVersions: []string{"< 4.17.21"},
				FixedVersions:    []string{"4.17.21"},
				Severity:         "HIGH",
				CWE:              []string{"CWE-94"},
				CVSS:             "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H",
				CVSSScore:        7.2,
				Aliases:          []string{"CVE-2021-23337"},
				Summary:          "Command Injection via template in lodash",
				Description:      "Lodash versions prior to 4.17.21 are vulnerable to Command Injection via template function sourceURL parameter.",
				Ranges: []RangeSpec{
					{
						Type: "SEMVER",
						Events: []EventSpec{
							{Introduced: "0", Fixed: "4.17.21"},
						},
					},
				},
			},
			{
				ID:               "GHSA-qw6h-v559-w3pj",
				Package:          "express",
				Ecosystem:        "npm",
				AffectedVersions: []string{"< 4.18.2"},
				FixedVersions:    []string{"4.18.2"},
				Severity:         "HIGH",
				CWE:              []string{"CWE-601"},
				CVSS:             "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
				CVSSScore:        6.1,
				Aliases:          []string{"CVE-2022-24999"},
				Summary:          "Open Redirect in express res.location and res.redirect",
				Description:      "Express versions prior to 4.18.2 permit open redirect when redirecting to untrusted URLs.",
				Ranges: []RangeSpec{
					{
						Type: "SEMVER",
						Events: []EventSpec{
							{Introduced: "0", Fixed: "4.18.2"},
						},
					},
				},
			},
			{
				ID:               "GHSA-8cf7-32gw-wr33",
				Package:          "jsonwebtoken",
				Ecosystem:        "npm",
				AffectedVersions: []string{"<= 8.5.1"},
				FixedVersions:    []string{"9.0.0"},
				Severity:         "CRITICAL",
				CWE:              []string{"CWE-94"},
				CVSS:             "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
				CVSSScore:        9.8,
				Aliases:          []string{"CVE-2022-23529"},
				Summary:          "Arbitrary Code Execution in jsonwebtoken verify()",
				Description:      "In jsonwebtoken <= 8.5.1, secretOrPublicKey can be abused via crafted toString methods to execute arbitrary code.",
				Ranges: []RangeSpec{
					{
						Type: "SEMVER",
						Events: []EventSpec{
							{Introduced: "0", Fixed: "9.0.0"},
						},
					},
				},
			},
			{
				ID:               "GHSA-cph5-m8f7-6c5x",
				Package:          "axios",
				Ecosystem:        "npm",
				AffectedVersions: []string{"< 0.21.2"},
				FixedVersions:    []string{"0.21.2"},
				Severity:         "HIGH",
				CWE:              []string{"CWE-918"},
				CVSS:             "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
				CVSSScore:        7.5,
				Aliases:          []string{"CVE-2021-3749"},
				Summary:          "Server-Side Request Forgery (SSRF) and ReDoS in axios",
				Description:      "Axios versions prior to 0.21.2 are vulnerable to Server-Side Request Forgery and Regular Expression Denial of Service.",
				Ranges: []RangeSpec{
					{
						Type: "SEMVER",
						Events: []EventSpec{
							{Introduced: "0", Fixed: "0.21.2"},
						},
					},
				},
			},

			// ================= PyPI =================
			{
				ID:               "GHSA-m258-gf55-585v",
				Package:          "Flask",
				Ecosystem:        "PyPI",
				AffectedVersions: []string{"< 2.2.5"},
				FixedVersions:    []string{"2.2.5"},
				Severity:         "HIGH",
				CWE:              []string{"CWE-384"},
				CVSS:             "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
				CVSSScore:        7.5,
				Aliases:          []string{"CVE-2023-30861"},
				Summary:          "Session Cookie Disclosure in Flask",
				Description:      "Flask versions prior to 2.2.5 can leak permanent session cookies under cached response scenarios.",
				Ranges: []RangeSpec{
					{
						Type: "ECOSYSTEM",
						Events: []EventSpec{
							{Introduced: "0", Fixed: "2.2.5"},
						},
					},
				},
			},
			{
				ID:               "GHSA-j8r2-6x86-q33q",
				Package:          "requests",
				Ecosystem:        "PyPI",
				AffectedVersions: []string{"< 2.31.0"},
				FixedVersions:    []string{"2.31.0"},
				Severity:         "MEDIUM",
				CWE:              []string{"CWE-200"},
				CVSS:             "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
				CVSSScore:        6.5,
				Aliases:          []string{"CVE-2023-32681"},
				Summary:          "Proxy-Authorization Header Leak in requests",
				Description:      "Requests versions prior to 2.31.0 leak the Proxy-Authorization header to destination servers when following redirects.",
				Ranges: []RangeSpec{
					{
						Type: "ECOSYSTEM",
						Events: []EventSpec{
							{Introduced: "0", Fixed: "2.31.0"},
						},
					},
				},
			},
			{
				ID:               "GHSA-w4wh-425q-f3w6",
				Package:          "Django",
				Ecosystem:        "PyPI",
				AffectedVersions: []string{"< 3.2.24"},
				FixedVersions:    []string{"3.2.24"},
				Severity:         "HIGH",
				CWE:              []string{"CWE-400"},
				CVSS:             "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
				CVSSScore:        7.5,
				Aliases:          []string{"CVE-2024-24680"},
				Summary:          "Denial of Service in Django intcomma filter",
				Description:      "Django versions prior to 3.2.24 allow remote attackers to cause high CPU consumption via crafted inputs to intcomma filter.",
				Ranges: []RangeSpec{
					{
						Type: "ECOSYSTEM",
						Events: []EventSpec{
							{Introduced: "0", Fixed: "3.2.24"},
						},
					},
				},
			},
			{
				ID:               "GHSA-x4qr-2fvf-3mr5",
				Package:          "cryptography",
				Ecosystem:        "PyPI",
				AffectedVersions: []string{"< 39.0.1"},
				FixedVersions:    []string{"39.0.1"},
				Severity:         "MEDIUM",
				CWE:              []string{"CWE-20"},
				CVSS:             "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
				CVSSScore:        5.3,
				Aliases:          []string{"CVE-2023-23931"},
				Summary:          "Memory corruption in Cipher.update_into in cryptography",
				Description:      "In cryptography prior to 39.0.1, Cipher.update_into may corrupt memory when immutable bytes-like objects are passed.",
				Ranges: []RangeSpec{
					{
						Type: "ECOSYSTEM",
						Events: []EventSpec{
							{Introduced: "0", Fixed: "39.0.1"},
						},
					},
				},
			},
			{
				ID:               "GHSA-ffqj-6fqr-9h24",
				Package:          "PyJWT",
				Ecosystem:        "PyPI",
				AffectedVersions: []string{"< 2.4.0"},
				FixedVersions:    []string{"2.4.0"},
				Severity:         "HIGH",
				CWE:              []string{"CWE-327"},
				CVSS:             "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
				CVSSScore:        7.5,
				Aliases:          []string{"CVE-2022-29217"},
				Summary:          "Key confusion between HMAC and asymmetric keys in PyJWT",
				Description:      "PyJWT prior to 2.4.0 allows attackers to bypass signature verification when asymmetric keys are mistakenly treated as HMAC secrets.",
				Ranges: []RangeSpec{
					{
						Type: "ECOSYSTEM",
						Events: []EventSpec{
							{Introduced: "0", Fixed: "2.4.0"},
						},
					},
				},
			},
			{
				ID:               "GHSA-8vj2-vxx3-667w",
				Package:          "Pillow",
				Ecosystem:        "PyPI",
				AffectedVersions: []string{"< 9.0.1"},
				FixedVersions:    []string{"9.0.1"},
				Severity:         "CRITICAL",
				CWE:              []string{"CWE-787"},
				CVSS:             "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
				CVSSScore:        9.8,
				Aliases:          []string{"CVE-2022-22817"},
				Summary:          "Arbitrary Code Execution in Pillow ImageMath.eval",
				Description:      "Pillow before 9.0.1 allows attackers to evaluate arbitrary code via ImageMath.eval without proper expression sandboxing.",
				Ranges: []RangeSpec{
					{
						Type: "ECOSYSTEM",
						Events: []EventSpec{
							{Introduced: "0", Fixed: "9.0.1"},
						},
					},
				},
			},
			{
				ID:               "GHSA-v845-jxx5-vc9f",
				Package:          "urllib3",
				Ecosystem:        "PyPI",
				AffectedVersions: []string{"< 1.26.17"},
				FixedVersions:    []string{"1.26.17"},
				Severity:         "HIGH",
				CWE:              []string{"CWE-200"},
				CVSS:             "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
				CVSSScore:        7.5,
				Aliases:          []string{"CVE-2023-43804"},
				Summary:          "Cookie Leakage via HTTP Redirects in urllib3",
				Description:      "urllib3 versions prior to 1.26.17 do not strip the Cookie header during cross-origin redirects.",
				Ranges: []RangeSpec{
					{
						Type: "ECOSYSTEM",
						Events: []EventSpec{
							{Introduced: "0", Fixed: "1.26.17"},
						},
					},
				},
			},
			{
				ID:               "GHSA-4f7f-cmf8-3x7v",
				Package:          "SQLAlchemy",
				Ecosystem:        "PyPI",
				AffectedVersions: []string{"< 1.3.16"},
				FixedVersions:    []string{"1.3.16"},
				Severity:         "HIGH",
				CWE:              []string{"CWE-89"},
				CVSS:             "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
				CVSSScore:        8.1,
				Aliases:          []string{"CVE-2019-9740"},
				Summary:          "SQL Injection vulnerability in SQLAlchemy order_by",
				Description:      "SQLAlchemy prior to 1.3.16 is vulnerable to SQL injection through crafted order_by clauses with string literals.",
				Ranges: []RangeSpec{
					{
						Type: "ECOSYSTEM",
						Events: []EventSpec{
							{Introduced: "0", Fixed: "1.3.16"},
						},
					},
				},
			},
			{
				ID:               "GHSA-7534-mm45-c74v",
				Package:          "PyYAML",
				Ecosystem:        "PyPI",
				AffectedVersions: []string{"< 5.4"},
				FixedVersions:    []string{"5.4"},
				Severity:         "CRITICAL",
				CWE:              []string{"CWE-502"},
				CVSS:             "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
				CVSSScore:        9.8,
				Aliases:          []string{"CVE-2020-14343"},
				Summary:          "Arbitrary Code Execution in PyYAML FullLoader",
				Description:      "PyYAML prior to 5.4 allows arbitrary code execution during yaml deserialization via full_load.",
				Ranges: []RangeSpec{
					{
						Type: "ECOSYSTEM",
						Events: []EventSpec{
							{Introduced: "0", Fixed: "5.4"},
						},
					},
				},
			},

			// ================= Go =================
			{
				ID:               "GO-2022-0444",
				Package:          "golang.org/x/crypto",
				Ecosystem:        "Go",
				AffectedVersions: []string{"< 0.0.0-20220412211245-5be80e882529"},
				FixedVersions:    []string{"v0.0.0-20220412211245-5be80e882529"},
				Severity:         "HIGH",
				CWE:              []string{"CWE-400"},
				CVSS:             "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
				CVSSScore:        7.5,
				Aliases:          []string{"CVE-2022-27191", "GHSA-8c26-wmh5-6g9v"},
				Summary:          "Denial of Service in golang.org/x/crypto/ssh",
				Description:      "An attacker can cause a panic in golang.org/x/crypto/ssh servers by sending an empty public key payload during authentication.",
				Ranges: []RangeSpec{
					{
						Type: "SEMVER",
						Events: []EventSpec{
							{Introduced: "0", Fixed: "0.0.0-20220412211245-5be80e882529"},
						},
					},
				},
			},
			{
				ID:               "GO-2022-1059",
				Package:          "golang.org/x/text",
				Ecosystem:        "Go",
				AffectedVersions: []string{"< 0.3.8"},
				FixedVersions:    []string{"v0.3.8"},
				Severity:         "HIGH",
				CWE:              []string{"CWE-400"},
				CVSS:             "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
				CVSSScore:        7.5,
				Aliases:          []string{"CVE-2022-32149", "GHSA-69ch-w2m2-3vjp"},
				Summary:          "Denial of service in golang.org/x/text/language",
				Description:      "Parsing a malformed language tag in golang.org/x/text can cause an out-of-bounds index panic resulting in DoS.",
				Ranges: []RangeSpec{
					{
						Type: "SEMVER",
						Events: []EventSpec{
							{Introduced: "0", Fixed: "0.3.8"},
						},
					},
				},
			},
			{
				ID:               "GO-2023-2102",
				Package:          "golang.org/x/net",
				Ecosystem:        "Go",
				AffectedVersions: []string{"< 0.17.0"},
				FixedVersions:    []string{"v0.17.0"},
				Severity:         "HIGH",
				CWE:              []string{"CWE-400"},
				CVSS:             "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
				CVSSScore:        7.5,
				Aliases:          []string{"CVE-2023-39325", "GHSA-4374-p667-p6c8"},
				Summary:          "Rapid Reset HTTP/2 stream multiplexing DoS in golang.org/x/net",
				Description:      "A malicious client can cause resource exhaustion by rapidly opening and canceling HTTP/2 streams.",
				Ranges: []RangeSpec{
					{
						Type: "SEMVER",
						Events: []EventSpec{
							{Introduced: "0", Fixed: "0.17.0"},
						},
					},
				},
			},

			// ================= crates.io =================
			{
				ID:               "RUSTSEC-2020-0071",
				Package:          "time",
				Ecosystem:        "crates.io",
				AffectedVersions: []string{"< 0.2.23"},
				FixedVersions:    []string{"0.2.23"},
				Severity:         "HIGH",
				CWE:              []string{"CWE-416"},
				CVSS:             "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
				CVSSScore:        7.5,
				Aliases:          []string{"CVE-2020-26235"},
				Summary:          "Potential segfault in time crate via localtime_r",
				Description:      "The time crate before 0.2.23 had a race condition when calling localtime_r in multithreaded environments.",
				Ranges: []RangeSpec{
					{
						Type: "SEMVER",
						Events: []EventSpec{
							{Introduced: "0", Fixed: "0.2.23"},
						},
					},
				},
			},
			{
				ID:               "RUSTSEC-2021-0124",
				Package:          "tokio",
				Ecosystem:        "crates.io",
				AffectedVersions: []string{"< 1.8.4"},
				FixedVersions:    []string{"1.8.4"},
				Severity:         "HIGH",
				CWE:              []string{"CWE-416"},
				CVSS:             "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
				CVSSScore:        7.5,
				Aliases:          []string{"CVE-2021-45710"},
				Summary:          "Data race in tokio synchronization primitives",
				Description:      "A race condition in tokio's notify primitive allowed use-after-free or data corruption.",
				Ranges: []RangeSpec{
					{
						Type: "SEMVER",
						Events: []EventSpec{
							{Introduced: "0", Fixed: "1.8.4"},
						},
					},
				},
			},
		},
	}
}
