package handler

import (
	"context"

	"github.com/995933447/easymicro/grpc"
	"github.com/995933447/fastlog"
	"github.com/995933447/rbac/rbac"
	"github.com/995933447/rbac/rbacserver/db"
	"go.mongodb.org/mongo-driver/bson"
)

func (s *RBAC) ListRole(ctx context.Context, req *rbac.ListRoleReq) (*rbac.ListRoleResp, error) {
	var resp rbac.ListRoleResp

	if !req.AllScope && req.Scope == "" {
		return nil, grpc.NewRPCErrWithMsg(rbac.ErrCode_ErrCodeInvalidParam, "scope is required when all_scope is false")
	}

	if req.Page == nil {
		return nil, grpc.NewRPCErrWithMsg(rbac.ErrCode_ErrCodeInvalidParam, "page is required")
	}

	filter := bson.M{}

	if req.Name != "" {
		filter["name"] = req.Name
	}

	if req.RoleId > 0 {
		filter["role_id"] = req.RoleId
	}

	if !req.AllScope && req.Scope != "" {
		filter["scope"] = req.Scope
	}

	if req.Status > 0 {
		filter["status"] = req.Status
	}

	if req.OnlySuperAdmin {
		filter["is_super_admin"] = true
	}

	if req.WithoutSuperAdmin {
		filter["is_super_admin"] = false
	}

	mod := db.NewRoleModel()
	total, err := mod.FindCount(ctx, filter)
	if err != nil {
		fastlog.Error(err)
		return nil, err
	}

	resp.Total = uint32(total)

	roles, err := mod.FindManyByPage(ctx, filter, bson.D{{"_id", -1}}, int64(req.Page.Page), int64(req.Page.PageSize))
	if err != nil {
		fastlog.Error(err)
		return nil, err
	}

	for _, role := range roles {
		resp.List = append(resp.List, &rbac.Role{
			RoleId:       role.RoleId,
			Name:         role.Name,
			Scope:        role.Scope,
			Status:       role.Status,
			PermIds:      role.PermIds,
			Remark:       role.Remark,
			IsSuperAdmin: role.IsSuperAdmin,
		})
	}

	return &resp, nil
}
