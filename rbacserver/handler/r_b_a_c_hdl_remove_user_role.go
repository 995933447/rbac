package handler

import (
	"context"

	"github.com/995933447/easymicro/grpc"
	"github.com/995933447/fastlog"
	"github.com/995933447/rbac/rbac"
	"github.com/995933447/rbac/rbacserver/db"
)

func (s *RBAC) RemoveUserRole(ctx context.Context, req *rbac.RemoveUserRoleReq) (*rbac.RemoveUserRoleResp, error) {
	var resp rbac.RemoveUserRoleResp

	if req.RoleId == 0 {
		return nil, grpc.NewRPCErrWithMsg(rbac.ErrCode_ErrCodeInvalidParam, "role_id is required")
	}

	if req.UserId == 0 {
		return nil, grpc.NewRPCErrWithMsg(rbac.ErrCode_ErrCodeInvalidParam, "user_id is required")
	}

	_, err := db.NewUserRoleModel().DeleteOneByUserIdAndRoleId(ctx, req.UserId, req.RoleId)
	if err != nil {
		fastlog.Error(err)
		return nil, err
	}

	return &resp, nil
}
