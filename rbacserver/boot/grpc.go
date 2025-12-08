package boot

import (
	"context"
	"fmt"

	easymicrogrpc "github.com/995933447/easymicro/grpc"
	"github.com/995933447/easymicro/grpc/interceptor"
	"github.com/995933447/idgen/idgen"
	"github.com/995933447/rbac/rbac"
	"github.com/995933447/rbac/rbacserver/config"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func RegisterGRPCDialOpts() {
	unaryInterceptors := []grpc.UnaryClientInterceptor{
		interceptor.RecoveryRPCUnaryInterceptor,
		interceptor.TraceRPCUnaryInterceptor,
		interceptor.RPCBreakerUnaryInterceptor,
		interceptor.FastlogRPCUnaryInterceptor,
	}
	config.SafeReadServerConfig(func(c *config.ServerConfig) {
		if !c.IsProd() {
			unaryInterceptors = append(unaryInterceptors, interceptor.NatsRPCFallbackInterceptor)
		}
	})

	easymicrogrpc.RegisterGlobalDialOpts(
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultServiceConfig(fmt.Sprintf(`{"loadBalancingPolicy": "%s"}`, easymicrogrpc.BalancerNameRoundRobin)),
		grpc.WithChainUnaryInterceptor(unaryInterceptors...),
		grpc.WithChainStreamInterceptor(
			interceptor.TraceRPCStreamInterceptor,
			interceptor.RPCBreakerStreamInterceptor,
			interceptor.FastlogRPCStreamInterceptor,
			interceptor.RecoveryRPCStreamInterceptor,
		),
	)
}

func PrepareDiscoverGRPC(ctx context.Context) error {
	var discoveryName string
	config.SafeReadServerConfig(func(c *config.ServerConfig) {
		c.GetDiscovery()
	})

	if err := rbac.PrepareGRPC(ctx, discoveryName); err != nil {
		return err
	}

	if err := idgen.PrepareGRPC(ctx, discoveryName); err != nil {
		return err
	}

	return nil
}
