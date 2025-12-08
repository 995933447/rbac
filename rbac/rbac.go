package rbac

import (
	"context"

	easymicrogrpc "github.com/995933447/easymicro/grpc"
)

func PrepareGRPC(ctx context.Context, discoveryName string) error {
	if err := easymicrogrpc.PrepareDiscoverGRPC(context.TODO(), EasymicroGRPCSchema, discoveryName); err != nil {
		return err
	}
	return nil
}
