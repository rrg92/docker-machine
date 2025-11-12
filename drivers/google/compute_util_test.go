package google

import (
	"slices"
	"testing"

	"github.com/rancher/machine/drivers/driverutil"
	"github.com/rancher/wrangler/v3/pkg/name"
	"github.com/stretchr/testify/assert"
	raw "google.golang.org/api/compute/v1"
)

func TestAllTagTypes(t *testing.T) {
	tags := parseTags(&Driver{
		OpenPorts: []string{
			"one",
			"two",
			"three",
		},
		Tags: "four,five,six",
	}, &ComputeUtil{
		externalFirewallRulePrefix: "outside",
		internalFirewallRulePrefix: "inside",
	})

	assert.Equal(t, []string{
		"four",
		"five",
		"six",
		name.SafeConcatName("inside", internalFirewallRuleSuffix),
		name.SafeConcatName("outside", externalFirewallRuleSuffix),
	}, tags)
}

func TestInternalOnlyTag(t *testing.T) {
	tags := parseTags(
		&Driver{},
		&ComputeUtil{
			internalFirewallRulePrefix: "inside",
		})

	assert.Equal(t, []string{name.SafeConcatName("inside", internalFirewallRuleSuffix)}, tags)
}

func TestExternalOnlyTag(t *testing.T) {
	tags := parseTags(&Driver{
		OpenPorts: []string{
			"123",
		},
	}, &ComputeUtil{
		externalFirewallRulePrefix: "outside",
		openPorts: []string{
			"123",
		},
	})

	assert.Equal(t, []string{name.SafeConcatName("outside", externalFirewallRuleSuffix)}, tags)
}

func TestPortsUsed(t *testing.T) {
	var tests = []struct {
		description   string
		computeUtil   *ComputeUtil
		expectedPorts []string
		expectedError error
	}{
		{"use swarm port", &ComputeUtil{SwarmMaster: true, SwarmHost: "tcp://host:3376"}, []string{"3376/tcp"}, nil},
		{"use non default swarm port", &ComputeUtil{SwarmMaster: true, SwarmHost: "tcp://host:4242"}, []string{"4242/tcp"}, nil},
		{"include additional ports", &ComputeUtil{openPorts: []string{"80", "2377/udp"}}, []string{"80/tcp", "2377/udp"}, nil},
	}

	for _, test := range tests {
		ports, err := test.computeUtil.portsUsed()

		assert.Equal(t, test.expectedPorts, ports)
		assert.Equal(t, test.expectedError, err)
	}
}

func TestUpdatePorts(t *testing.T) {
	t.Parallel()

	var tests = []struct {
		name          string
		rule          *raw.Firewall
		incomingPorts []string
		diffExpected  bool
	}{
		{
			name: "no change",
			rule: &raw.Firewall{
				Allowed: []*raw.FirewallAllowed{
					{
						IPProtocol: "tcp",
						Ports:      []string{"80", "443"},
					},
				},
			},
			incomingPorts: []string{"443", "80"},
			diffExpected:  false,
		},
		{
			name: "add ports",
			rule: &raw.Firewall{
				Allowed: []*raw.FirewallAllowed{
					{
						IPProtocol: "tcp",
						Ports:      []string{"80"},
					},
				},
			},
			incomingPorts: []string{"80/tcp", "443/tcp", "123/udp"},
			diffExpected:  true,
		},
		{
			name: "remove ports",
			rule: &raw.Firewall{
				Allowed: []*raw.FirewallAllowed{
					{
						IPProtocol: "tcp",
						Ports:      []string{"80", "443"},
					},
					{
						IPProtocol: "udp",
						Ports:      []string{"123"},
					},
				},
			},
			incomingPorts: []string{"80/tcp"},
			diffExpected:  true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			diff := updatePorts(tt.rule, tt.incomingPorts)
			if diff && !tt.diffExpected {
				t.Logf("expected change to be %t, but got %t", tt.diffExpected, diff)
				t.Fail()
			}

			var udpPorts, tcpPorts []string
			for _, allowed := range tt.rule.Allowed {
				if allowed.IPProtocol == "udp" {
					udpPorts = allowed.Ports
				}
				if allowed.IPProtocol == "tcp" {
					tcpPorts = allowed.Ports
				}
			}

			for _, p := range tt.incomingPorts {
				port, proto := driverutil.SplitPortProto(p)
				switch proto {
				case "udp":
					if !slices.Contains(udpPorts, port) {
						t.Logf("expected port %s to be in allowed list", port)
						t.Fail()
					}
				default:
					if !slices.Contains(tcpPorts, port) {
						t.Logf("expected port %s to be in allowed list", port)
						t.Fail()
					}
				}
			}
		})
	}
}

func TestParseLabels(t *testing.T) {
	t.Parallel()
	var tests = []struct {
		name     string
		labels   string
		expected map[string]string
	}{
		{
			"empty",
			"",
			map[string]string{},
		},
		{
			"valid label",
			"one,two",
			map[string]string{
				"one": "two",
			},
		},
		{
			"valid labels",
			"one,two,three,four",
			map[string]string{
				"one":   "two",
				"three": "four",
			},
		},
		{
			"invalid format",
			"one,two,three",
			map[string]string{
				"one": "two",
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, parseLabels(tt.labels))
		})
	}
}
