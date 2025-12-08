package handler

import (
	"context"

	"github.com/995933447/easymicro/grpc"
	"github.com/995933447/fastlog"
	"github.com/995933447/rbac/rbac"
	"github.com/995933447/rbac/rbacserver/db"
	"go.mongodb.org/mongo-driver/bson"
)

func (s *RBAC) CheckPerm(ctx context.Context, req *rbac.CheckPermReq) (*rbac.CheckPermResp, error) {
	var resp rbac.CheckPermResp

	if req.UserId == 0 {
		return nil, grpc.NewRPCErrWithMsg(rbac.ErrCode_ErrCodeInvalidParam, "user_id is required")
	}

	if req.ResourceRoute == "" && req.ResourceService == "" {
		return nil, grpc.NewRPCErrWithMsg(rbac.ErrCode_ErrCodeInvalidParam, "one of resource_route or resource_service is required")
	}

	userRoles, err := db.NewUserRoleModel().FindAll(ctx, bson.M{"user_id": req.UserId, "scope": req.Scope})
	if err != nil {
		fastlog.Error(err)
		return nil, err
	}

	var roleIds []uint64
	for _, userRole := range userRoles {
		if userRole.Status != int32(rbac.UserRoleStatus_UserRoleStatusNormal) {
			continue
		}

		roleIds = append(roleIds, userRole.RoleId)
	}
	roles, err := db.NewRoleModel().FindAll(ctx, bson.M{"role_id": bson.M{"$in": roleIds}})
	if err != nil {
		fastlog.Error(err)
		return nil, err
	}

	myPermIdSet := make(map[uint64]struct{})
	for _, role := range roles {
		if role.Scope != req.Scope {
			fastlog.Warnf("role(id:%d, name:%s)'s scope is %s, not %s", role.RoleId, role.Name, role.Scope, req.Scope)
			continue
		}

		if role.Status != int32(rbac.RoleStatus_RoleStatusNormal) {
			continue
		}

		if role.IsSuperAdmin {
			return &resp, nil
		}

		for _, permId := range role.PermIds {
			myPermIdSet[permId] = struct{}{}
		}
	}
	perms, err := db.NewPermModel().FindAll(ctx, bson.M{"scope": req.Scope})
	if err != nil {
		fastlog.Error(err)
		return nil, err
	}

	var (
		permMap            = make(map[uint64]*rbac.PermOrm)
		myResourceRoutes   = make(map[string]*rbac.PermOrm)
		myResourceServices = make(map[string][]*rbac.PermOrm)
	)
	for _, perm := range perms {
		if perm.Scope != req.Scope {
			fastlog.Warnf("perm(id:%d, name:%s)'s scope is %s, not %s", perm.PermId, perm.Name, perm.Scope, req.Scope)
			continue
		}

		permMap[perm.PermId] = perm

		_, ok := myPermIdSet[perm.PermId]
		if ok {
			myResourceRoutes[perm.ResourceRoute] = perm
			for _, service := range perm.ResourceServices {
				ps := myResourceServices[service.Service]
				myResourceServices[service.Service] = append(ps, perm)
			}
		}
	}

	// 检查是否有所有上级菜单的权限
	checkHasPermAccessParent := func(perm *rbac.PermOrm) (bool, error) {
		checkedPermIds := map[uint64]struct{}{
			perm.PermId: {},
		}

		// 没有父亲节点
		if perm.Pid == 0 {
			return true, nil
		}

		parent, ok := permMap[perm.Pid]
		if !ok {
			return false, nil
		}

		for {
			if _, ok = checkedPermIds[parent.PermId]; ok {
				return false, grpc.NewRPCErr(rbac.ErrCode_ErrCodePermDeadLoop)
			}

			if _, ok = myResourceRoutes[parent.ResourceRoute]; !ok {
				return false, nil
			}

			// 顶部节点
			if parent.Pid == 0 {
				break
			}

			checkedPermIds[parent.PermId] = struct{}{}

			parent, ok = permMap[parent.Pid]
			if !ok {
				return false, nil
			}
		}

		return true, nil
	}

	if req.ResourceRoute != "" {
		perm, ok := myResourceRoutes[req.ResourceRoute]
		if !ok {
			resp.Rejected = true
			return &resp, nil
		}

		var passCheck bool
		if req.ResourceService != "" {
			for _, service := range perm.ResourceServices {
				if req.ResourceService == service.Service {
					passCheck = true
					break
				}
			}
		} else {
			passCheck = true
		}
		if !passCheck {
			resp.Rejected = true
			return &resp, nil
		}

		ok, err = checkHasPermAccessParent(perm)
		if err != nil {
			return nil, err
		}

		if !ok {
			resp.Rejected = true
		}

		return &resp, nil
	}

	if req.ResourceService != "" {
		ps, ok := myResourceServices[req.ResourceService]
		if !ok {
			resp.Rejected = true
			return &resp, nil
		}

		var passCheck bool
		for _, perm := range ps {
			passCheck, err = checkHasPermAccessParent(perm)
			if err != nil {
				return nil, err
			}

			if passCheck {
				break
			}
		}
		if !passCheck {
			resp.Rejected = true
		}
	}

	return &resp, nil
}
