// Copyright 2019-2021 The Inspektor Gadget authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/kinvolk/inspektor-gadget/cmd/kubectl-gadget/utils"
	gadgetv1alpha1 "github.com/kinvolk/inspektor-gadget/pkg/api/v1alpha1"
)

var seccompAdvisorCmd = &cobra.Command{
	Use:   "seccomp-advisor",
	Short: "Generate seccomp policies based on recorded syscalls activity",
}

var seccompAdvisorStartCmd = &cobra.Command{
	Use:   "start",
	Short: "Start to monitor the system calls",
	RunE:   runSeccompAdvisorStart,
	SilenceUsage: true,
}

var seccompAdvisorStopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop monitoring and report the policies",
	RunE:   runSeccompAdvisorStop,
	SilenceUsage: true,
}

var seccompAdvisorListCmd = &cobra.Command{
	Use:   "list",
	Short: "List existing seccomp traces",
	RunE:   runSeccompAdvisorList,
	SilenceUsage: true,
}

var (
	outputMode string
	seccompProfileName string
)

func init() {
	// Add generic information.
	rootCmd.AddCommand(seccompAdvisorCmd)
	utils.AddCommonFlags(seccompAdvisorCmd, &params)

	seccompAdvisorCmd.AddCommand(seccompAdvisorStartCmd)
	seccompAdvisorStartCmd.PersistentFlags().StringVarP(&outputMode, "output-mode", "m", "Status", "The trace output mode, possibles values are ExternalResource or Status (default).")
	seccompAdvisorStartCmd.PersistentFlags().StringVar(&seccompProfileName, "seccomp-profile-name", "", "The seccomp profile which will be created when using ExternalResource as value for --output-mode.")

	seccompAdvisorCmd.AddCommand(seccompAdvisorStopCmd)
	seccompAdvisorCmd.AddCommand(seccompAdvisorListCmd)
}

// runSeccompAdvisorStart starts monitoring of syscalls for the given
// parameters.
func runSeccompAdvisorStart(cmd *cobra.Command, args []string) error {
	if params.Podname == "" {
		return errors.New("Usage: kubectl gadget seccompadvisor start -p podname")
	}

	config := &utils.TraceConfig{
		GadgetName:      "seccomp",
		Operation:       "start",
		TraceOutputMode: outputMode,
		TraceOutput:     seccompProfileName,
		CommonFlags:     &params,
	}

	traceID, err := utils.CreateTrace(config)
	if err != nil {
		return err
	}

	fmt.Printf("%s\n", traceID)

	return nil
}

// runSeccompAdvisorStop reports an already running trace which ID was given
// as parameter.
func runSeccompAdvisorStop(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		return errors.New("Usage: kubectl gadget seccomp-advisor stop global-trace-id\n")
	}

	callback := func(results []gadgetv1alpha1.Trace) error {
		for _, i := range results {
			if i.Spec.OutputMode == "ExternalResource" {
				fmt.Printf("Succesfully created seccomp profile %q!\n", i.Spec.Output)
			} else {
				fmt.Printf("%v\n", i.Status.Output)
			}
		}

		return nil
	}

	traceID := args[0]

	err := utils.SetTraceOperation(traceID, "generate")
	if err != nil {
		return err
	}

	// We stop the trace so its Status.State become Stopped.
	// Indeed, generate operation does not change value of Status.State.
	err = utils.SetTraceOperation(traceID, "stop")
	if err != nil {
		return err
	}

	err = utils.PrintTraceOutputFromStatus(traceID, "Stopped", callback)
	if err != nil {
		return err
	}

	// WARNING We should defer this call, but trace can sadly timeout, so it is
	// better for the user to call this function again to get expected result and
	// delete the trace at the same time.
	return utils.DeleteTrace(traceID)
}

// runSeccompAdvisorList lists already running traces which config was given as
// parameter.
func runSeccompAdvisorList(cmd *cobra.Command, args []string) error {
	config := &utils.TraceConfig{
		GadgetName:  "seccomp",
		CommonFlags: &params,
	}

	err := utils.PrintAllTraces(config)
	if err != nil {
		return err
	}

	return nil
}
