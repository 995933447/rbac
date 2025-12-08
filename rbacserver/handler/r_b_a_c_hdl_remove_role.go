package handler

import (
	"context"

	"github.com/995933447/easymicro/grpc"
	"github.com/995933447/fastlog"
	"github.com/995933447/rbac/rbac"
	"github.com/995933447/rbac/rbacserver/db"
	"go.mongodb.org/mongo-driver/bson"
)

func (s *RBAC) RemoveRole(ctx context.Context, req *rbac.RemoveRoleReq) (*rbac.RemoveRoleResp, error) {
	var resp rbac.RemoveRoleResp

	if req.RoleId == 0 {
		return nil, grpc.NewRPCErrWithMsg(rbac.ErrCode_ErrCodeInvalidParam, "role_id is required")
	}

	count, err := db.NewUserRoleModel().FindCount(ctx, bson.M{
		"role_id": req.RoleId,
	})
	if err != nil {
		fastlog.Error(err)
		return nil, err
	}

	if count > 0 {
		if !req.AutoRemoveUserRoles {
			return nil, grpc.NewRPCErr(rbac.ErrCode_ErrCodeRoleUsedByUser)
		}

		_, err = db.NewRoleModel().DeleteOneByRoleId(ctx, req.RoleId)
		if err != nil {
			fastlog.Error(err)
			return nil, err
		}

		_, err = db.NewUserRoleModel().DeleteManyByRoleId(ctx, req.RoleId)
		if err != nil {
			fastlog.Error(err)
			return nil, err
		}

		return &resp, nil
	}

	_, err = db.NewRoleModel().DeleteOneByRoleId(ctx, req.RoleId)
	if err != nil {
		fastlog.Error(err)
		return nil, err
	}

	return &resp, nil
}
