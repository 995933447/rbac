package handler

import (
	"github.com/995933447/rbac/rbac"
)

type RBAC struct {
	rbac.UnimplementedRBACServer
	ServiceName string
}

var RBACHandler = &RBAC{
	ServiceName: rbac.EasymicroGRPCPbServiceNameRBAC,
}
