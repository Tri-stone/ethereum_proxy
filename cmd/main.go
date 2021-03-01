/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main


import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
	"go.uber.org/zap"

	"github.com/Tri-stone/xuperchain/ethereum_proxy"
	"github.com/xuperchain/xuperchain/core/pb"
)

var proxyCmd = &cobra.Command{
	Use:   "proxy",
	Short: "proxy is a web3 provider used to interact with the EVM chaincode on a XuperChain Network. The flags provided will be honored over the corresponding environment variables.",
	Long:  "proxy is a web3 provider used to interact with the EVM chaincode on a Fabric Network. The flags provided will be honored over the corresponding environment variables.",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		err := checkFlags()
		if err != nil {
			return err
		}

		// At this point all of our flags have been validated
		// Usage no longer needs to be provided for the errors that follow
		cmd.SilenceUsage = true
		return runProxy(cmd, args)
	},
}

var cfg string
var port int

// InitFlags sets up the flags and environment variables for Proxy
func initFlags() {
	viper.BindEnv("config")
	viper.BindEnv("port")

	proxyCmd.PersistentFlags().StringVarP(&cfg, "config", "c", "",
		"Path to a compatible Fabric SDK Go config file. This flag is required if PROXY_CONFIG is not set.")
	viper.BindPFlag("config", proxyCmd.PersistentFlags().Lookup("config"))


	//Port defaults to 5000 if PORT is not set or `-p,-port` is not provided
	proxyCmd.PersistentFlags().IntVarP(&port, "port", "p", 5000,
		"Port that Proxy will be running on. The listening port can also be set by the PROXY_PORT environment variable.")
	viper.BindPFlag("port", proxyCmd.PersistentFlags().Lookup("port"))
}

// Viper takes care of precedence of Flags and Environment variables
// Flag values are taken over environment variables
// Both CCID and Port have defaults so do not need to be provided.
func checkFlags() error {
	cfg = viper.GetString("config")
	if cfg == "" {
		return fmt.Errorf("Missing config. Please use flag --config or set PROXY_CONFIG")
	}

	port = viper.GetInt("port")
	return nil
}

// Runs Proxy
// Will exit gracefully for errors and signal interrupts
func runProxy(cmd *cobra.Command, args []string) error {

	xchainClient, eventClient, err := initXchainClient(cfg)
	if err != nil {
		return fmt.Errorf("Failed to create xchainClient: %s\n", err)
	}

	rawLogger, err := zap.NewProduction()
	if err != nil {
		return fmt.Errorf("Failed to create logger: %s\n", err)
	}
	logger := rawLogger.Named("proxy").Sugar()

	ethService := ethereum_proxy.NewEthService(xchainClient, eventClient, logger)

	proxy := ethereum_proxy.NewEthereumProxy(ethService, port)

	errChan := make(chan error, 1)
	go func() {
		errChan <- proxy.Start()
	}()
	logger.Infow("Starting Proxy", "port", port)

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)

	select {
	case err = <-errChan:
	case <-signalChan:
		logger.Info("Received termination signal")
		err = proxy.Shutdown()
	}

	if err != nil {
		logger.Infow("Proxy exited with error", "error", err)
		return err
	}
	logger.Info("Proxy exited")
	return nil
}

func main() {
	initFlags()
	if proxyCmd.Execute() != nil {
		os.Exit(1)
	}
}

func initXchainClient(host string) (pb.XchainClient, pb.EventServiceClient, error) {
	conn, err := grpc.Dial(host, grpc.WithInsecure(), grpc.WithMaxMsgSize(64<<20-1))
	if err != nil {
		return nil, nil, err
	}
	return pb.NewXchainClient(conn), pb.NewEventServiceClient(conn), nil
}