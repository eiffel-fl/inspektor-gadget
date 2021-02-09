package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"google.golang.org/grpc"

	pb "github.com/kinvolk/inspektor-gadget/pkg/gadgettracermanager/api"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgettracermanager/containerutils"

	"github.com/containerd/nri/skel"
	types "github.com/containerd/nri/types/v1"
)

// TODO: Understand why using github.com/containerd/pkg/cri/annonations
// creates a hell dependency problem with k8s.io packages.
const (
	// SandboxNamespace is the name of the namespace of the sandbox (pod)
	SandboxNamespace = "io.kubernetes.cri.sandbox-namespace"

	// SandboxName is the name of the sandbox (pod)
	SandboxName = "io.kubernetes.cri.sandbox-name"

	// ContainerName is the name of the container in the pod
	ContainerName = "io.kubernetes.cri.container-name"
)

var (
	socketfile string
)

func init() {
	flag.StringVar(&socketfile, "socketfile", "/run/gadgettracermanager.socket", "Socket file")
}

type igHook struct {
}

func (i *igHook) Type() string {
	return "ighook"
}

func (i *igHook) Invoke(ctx context.Context, r *types.Request) (*types.Result, error) {
	// Ignore sandbox containers
	if !r.IsSandbox() && (r.State == types.Create || r.State == types.Delete) {
		processContainer(r)
	}

	result := r.NewResult("ighook")
	return result, nil
}

func main() {
	ctx := context.Background()
	if err := skel.Run(ctx, &igHook{}); err != nil {
		fmt.Fprintf(os.Stderr, "Error executing ighook: %v", err)
		// don't return an error as it's a debug tool and we don't want to
		// create extra trouble if there is a failure.
		os.Exit(0)
	}
}

func processContainer(r *types.Request) error {
	// Validate state
	if r.ID == "" || (r.Pid == 0 && r.State == types.Create) {
		return fmt.Errorf("invalid OCI state: %v %v", r.ID, r.Pid)
	}

	// Connect to the Gadget Tracer Manager
	var client pb.GadgetTracerManagerClient
	var ctx context.Context
	var cancel context.CancelFunc
	conn, err := grpc.Dial("unix://"+socketfile, grpc.WithInsecure())
	if err != nil {
		return err
	}
	defer conn.Close()
	client = pb.NewGadgetTracerManagerClient(conn)
	ctx, cancel = context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	// Handle the poststop hook first
	if r.State == types.Delete {
		_, err := client.RemoveContainer(ctx, &pb.ContainerDefinition{
			ContainerId: r.ID,
		})
		return err
	}

	// TODO: NRI includes a cgroup path, can that be used?
	// Get cgroup paths
	_, cgroupPathV2, err := containerutils.GetCgroupPaths(r.Pid)
	if err != nil {
		return err
	}
	cgroupPathV2WithMountpoint, _ := containerutils.CgroupPathV2AddMountpoint(cgroupPathV2)

	// Get cgroup-v2 id
	cgroupId, _ := containerutils.GetCgroupID(cgroupPathV2WithMountpoint)

	// Get mount namespace ino
	mntns, err := containerutils.GetMntNs(r.Pid)
	if err != nil {
		return err
	}

	labels := []*pb.Label{}

	for key, value := range r.Labels {
		label := &pb.Label{
			Key:   key,
			Value: value,
		}
		labels = append(labels, label)
	}

	namespace, _ := r.Spec.Annotations[SandboxNamespace]
	containerName, _ := r.Spec.Annotations[ContainerName]
	podName, _ := r.Spec.Annotations[SandboxName]

	_, err = client.AddContainer(ctx, &pb.ContainerDefinition{
		ContainerId:   r.ID,
		CgroupPath:    cgroupPathV2WithMountpoint,
		CgroupId:      cgroupId,
		Mntns:         mntns,
		Labels:        labels,
		Namespace:     namespace,
		Podname:       podName,
		ContainerName: containerName,
	})
	return err
}
