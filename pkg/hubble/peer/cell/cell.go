// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cell

import (
	"fmt"
	"log/slog"
	"net"
	"strconv"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/crypto/certloader"
	"github.com/cilium/cilium/pkg/hubble/peer"
	"github.com/cilium/cilium/pkg/hubble/peer/serviceoption"
	"github.com/cilium/cilium/pkg/logging/logfields"
	nodeManager "github.com/cilium/cilium/pkg/node/manager"
	"github.com/cilium/cilium/pkg/promise"
)

// Cell provides the Hubble peer service that handles peer discovery and notifications.
var Cell = cell.Module(
	"hubble-peer-service",
	"Hubble peer service for handling peer discovery and notifications",

	cell.Provide(newPeerService),
)

// HubbleConfig interface defines the configuration needed by the peer service
type HubbleConfig interface {
	GetListenAddress() string
	GetPreferIPv6() bool
}

type peerServiceParams struct {
	cell.In

	Logger           *slog.Logger
	NodeManager      nodeManager.NodeManager
	TLSConfigPromise tlsConfigPromise `optional:"true"`
	Config           HubbleConfig
}

type tlsConfigPromise promise.Promise[*certloader.WatchedServerConfig]

// PeerService provides the Hubble peer service.
type PeerService interface {
	Service() *peer.Service
}

type peerServiceImpl struct {
	service *peer.Service
}

func (p *peerServiceImpl) Service() *peer.Service {
	return p.service
}

// getPort extracts the port from an address string.
// Supports formats like ":4244", "localhost:4244", "[::1]:4244"
func getPort(addr string) (int, error) {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return 0, fmt.Errorf("parse host address and port: %w", err)
	}
	portNum, err := strconv.Atoi(port)
	if err != nil {
		return 0, fmt.Errorf("parse port number: %w", err)
	}
	return portNum, nil
}

func newPeerService(params peerServiceParams) (PeerService, error) {
	var peerServiceOptions []serviceoption.Option

	// Determine if TLS is enabled
	tlsEnabled := params.TLSConfigPromise != nil
	if !tlsEnabled {
		peerServiceOptions = append(peerServiceOptions, serviceoption.WithoutTLSInfo())
	}

	// Set address family preference
	if params.Config.GetPreferIPv6() {
		peerServiceOptions = append(peerServiceOptions, serviceoption.WithAddressFamilyPreference(serviceoption.AddressPreferIPv6))
	}

	// Extract port from listen address if available
	if addr := params.Config.GetListenAddress(); addr != "" {
		port, err := getPort(addr)
		if err != nil {
			// TODO: bubble up the error and/or set cell health as degraded
			params.Logger.Warn(
				"Hubble server will not pass port information in change notifications on exposed Hubble peer service",
				logfields.Error, err,
				logfields.Address, addr,
			)
		} else {
			peerServiceOptions = append(peerServiceOptions, serviceoption.WithHubblePort(port))
		}
	}

	service := peer.NewService(params.NodeManager, peerServiceOptions...)

	return &peerServiceImpl{
		service: service,
	}, nil
}
