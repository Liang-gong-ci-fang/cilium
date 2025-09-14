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

func TestHubbleConfigProvider(t *testing.T) {
	// Test that the HubbleConfig provider works correctly
	var providedConfig peercell.HubbleConfig

	testHive := hive.New(
		// Test with a minimal cell that includes the HubbleConfig provider
		cell.Module("test-hubble-config",
			"Test module for HubbleConfig provider",
			Core,
			cell.Provide(func(cfg config) peercell.HubbleConfig { return cfg }),
		),
		cell.Invoke(func(cfg peercell.HubbleConfig) {
			providedConfig = cfg
		}),
	)

	err := testHive.Populate(hivetest.Logger(t))
	require.NoError(t, err, "Failed to populate test hive")

	// Verify that HubbleConfig was provided and is not nil
	assert.NotNil(t, providedConfig, "HubbleConfig should be provided")

	// Test the default configuration values
	assert.Empty(t, providedConfig.GetListenAddress(), "Default listen address should be empty")
	assert.False(t, providedConfig.GetPreferIPv6(), "Default prefer IPv6 should be false")
}

func TestHubbleConfigProviderWithCustomConfig(t *testing.T) {
	// Test with custom configuration
	customConfig := config{
		ListenAddress: "0.0.0.0:4244",
		PreferIpv6:    true,
	}

	var providedConfig peercell.HubbleConfig

	testHive := hive.New(
		cell.Group(
			cell.Provide(func(config) peercell.HubbleConfig { return customConfig }),
			cell.Config(customConfig),
		),
		cell.Invoke(func(cfg peercell.HubbleConfig) {
			providedConfig = cfg
		}),
	)

	err := testHive.Populate(hivetest.Logger(t))
	require.NoError(t, err, "Failed to populate test hive with custom config")

	// Verify custom configuration values
	assert.Equal(t, "0.0.0.0:4244", providedConfig.GetListenAddress())
	assert.True(t, providedConfig.GetPreferIPv6())
}

func TestConfigImplementsHubbleConfigInterface(t *testing.T) {
	// Test that our config type properly implements the HubbleConfig interface
	cfg := config{
		ListenAddress: "127.0.0.1:4244",
		PreferIpv6:    false,
	}

	// This should compile without issues if config implements HubbleConfig
	var hubbleConfig peercell.HubbleConfig = cfg

	assert.Equal(t, "127.0.0.1:4244", hubbleConfig.GetListenAddress())
	assert.False(t, hubbleConfig.GetPreferIPv6())
}

func TestInterfaceAdapters(t *testing.T) {
	// Test the InterfaceAdapters group specifically
	var providedConfig peercell.HubbleConfig

	testHive := hive.New(
		Core,
		InterfaceAdapters,
		cell.Invoke(func(cfg peercell.HubbleConfig) {
			providedConfig = cfg
		}),
	)

	err := testHive.Populate(hivetest.Logger(t))
	require.NoError(t, err, "Failed to populate test hive with InterfaceAdapters")

	// Verify that HubbleConfig was provided by InterfaceAdapters
	assert.NotNil(t, providedConfig, "HubbleConfig should be provided by InterfaceAdapters")

	// Test with default config values
	assert.Empty(t, providedConfig.GetListenAddress())
	assert.False(t, providedConfig.GetPreferIPv6())
}
