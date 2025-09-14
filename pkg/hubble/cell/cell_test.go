// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package hubblecell

import (
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/hive"
	peercell "github.com/cilium/cilium/pkg/hubble/peer/cell"
)

func TestConfigProviders(t *testing.T) {
	// Test that Core and ConfigProviders work together with default config
	var providedConfig *peercell.HubbleConfig

	testHive := hive.New(
		Core,
		ConfigProviders,
		// Need certloader group to provide certloaderConfig
		certloaderGroup,
		cell.Invoke(func(cfg *peercell.HubbleConfig) {
			providedConfig = cfg
		}),
	)

	err := testHive.Populate(hivetest.Logger(t))
	require.NoError(t, err, "Failed to populate test hive with ConfigProviders")

	// Verify that HubbleConfig was provided by ConfigProviders
	assert.NotNil(t, providedConfig, "HubbleConfig should be provided by ConfigProviders")

	// Test with default config values
	assert.Empty(t, providedConfig.ListenAddress, "Default listen address should be empty")
	assert.False(t, providedConfig.PreferIpv6, "Default prefer IPv6 should be false")
	assert.False(t, providedConfig.EnableServerTLS, "Default should have TLS disabled (EnableServerTLS=false)")

	// Test the HubbleConfig struct directly with custom values
	customConfig := &peercell.HubbleConfig{
		ListenAddress:   "0.0.0.0:4244",
		PreferIpv6:      true,
		EnableServerTLS: true, // TLS enabled
	}

	// Test struct fields with custom values
	assert.Equal(t, "0.0.0.0:4244", customConfig.ListenAddress, "Custom listen address should match")
	assert.True(t, customConfig.PreferIpv6, "Custom prefer IPv6 should be true")
	assert.True(t, customConfig.EnableServerTLS, "TLS should be enabled (EnableServerTLS=true)")

	// Test with TLS disabled
	tlsDisabledConfig := &peercell.HubbleConfig{
		ListenAddress:   "0.0.0.0:4244",
		PreferIpv6:      true,
		EnableServerTLS: false, // TLS disabled
	}
	assert.False(t, tlsDisabledConfig.EnableServerTLS, "TLS should be disabled (EnableServerTLS=false)")
}
