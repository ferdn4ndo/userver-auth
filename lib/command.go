package lib

import "github.com/spf13/cobra"

// CommandRunner is invoked by fx after dependency injection.
type CommandRunner interface{}

// Command implements a cobra subcommand.
type Command interface {
	Short() string
	Setup(cmd *cobra.Command)
	Run() CommandRunner
}
