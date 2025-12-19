package handler

import (
	"context"

	"github.com/995933447/easymicro/grpc"
	"github.com/995933447/fastlog"
	"github.com/995933447/rbac/rbac"
	"github.com/995933447/rbac/rbacserver/db"
	"go.mongodb.org/mongo-driver/bson"
)

func (s *RBAC) ListUserRole(ctx context.Context, req *rbac.ListUserRoleReq) (*rbac.ListUserRoleResp, error) {
	var resp rbac.ListUserRoleResp

	if !req.AllScope && req.Scope == "" {
		return nil, grpc.NewRPCErrWithMsg(rbac.ErrCode_ErrCodeInvalidParam, "scope is required when all_scope is false")
	}

	filter := bson.M{}

	if !req.AllScope && req.Scope != "" {
		filter["scope"] = req.Scope
	}

	if req.Status > 0 {
		filter["status"] = req.Status
	}

	if req.UserId > 0 {
		filter["user_id"] = req.UserId
	}

	if req.RoleId > 0 {
		filter["role_id"] = req.RoleId
	}

	mod := db.NewUserRoleModel()
	total, err := mod.FindCount(ctx, filter)
	if err != nil {
		fastlog.Error(err)
		return nil, err
	}

	resp.Total = uint32(total)

	var page, pageSize uint32
	if req.Page != nil {
		page = req.Page.Page
		pageSize = req.Page.PageSize
	}

	userRoles, err := mod.FindManyByPage(ctx, filter, bson.D{{"_id", -1}}, int64(page), int64(pageSize))
	if err != nil {
		fastlog.Error(err)
		return nil, err
	}

	for _, userRole := range userRoles {
		resp.List = append(resp.List, &rbac.ListUserRoleResp_Item{
			UserRole: &rbac.UserRole{
				UserId: userRole.UserId,
				RoleId: userRole.RoleId,
				Scope:  userRole.Scope,
				Status: userRole.Status,
			},
			Id: userRole.ID.Hex(),
		})
	}

	return &resp, nil
}
