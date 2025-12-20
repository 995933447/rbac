package handler

import (
	"context"

	"github.com/995933447/easymicro/grpc"
	"github.com/995933447/fastlog"
	"github.com/995933447/rbac/rbac"
	"github.com/995933447/rbac/rbacserver/db"
	"go.mongodb.org/mongo-driver/bson"
)

func (s *RBAC) ListPerm(ctx context.Context, req *rbac.ListPermReq) (*rbac.ListPermResp, error) {
	var resp rbac.ListPermResp

	if !req.AllScope && req.Scope == "" {
		return nil, grpc.NewRPCErrWithMsg(rbac.ErrCode_ErrCodeInvalidParam, "scope is required when all_scope is false")
	}

	filter := bson.M{}

	if req.Name != "" {
		filter["name"] = req.Name
	}

	if !req.AllScope && req.Scope != "" {
		filter["scope"] = req.Scope
	}

	if req.PermId > 0 {
		filter["perm_id"] = req.PermId
	}

	if req.Pid > 0 {
		filter["pid"] = req.Pid
	}

	mod := db.NewPermModel()
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

	perms, err := mod.FindManyByPage(ctx, filter, bson.D{{"_id", -1}}, int64(page), int64(pageSize))
	if err != nil {
		fastlog.Error(err)
		return nil, err
	}

	for _, perm := range perms {
		var resourceServices []*rbac.ResourceService
		for _, svc := range perm.ResourceServices {
			resourceServices = append(resourceServices, &rbac.ResourceService{
				Service: svc.Service,
				Extra:   svc.Extra,
			})
		}
		resp.List = append(resp.List, &rbac.Perm{
			PermId:           perm.PermId,
			Name:             perm.Name,
			Scope:            perm.Scope,
			Pid:              perm.Pid,
			ResourceRoute:    perm.ResourceRoute,
			ResourceServices: resourceServices,
			ResourceType:     perm.ResourceType,
		})
	}

	return &resp, nil
}
