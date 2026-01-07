package handler

import (
	"context"

	"github.com/995933447/easymicro/grpc"
	"github.com/995933447/elemutil"
	"github.com/995933447/fastlog"
	"github.com/995933447/mconfigcenter-dashboard/backend/api/commonerr"
	"github.com/995933447/rbac/rbac"
	"github.com/995933447/rbac/rbacserver/db"
	"go.mongodb.org/mongo-driver/bson"
)

func (s *RBAC) OverwriteUserRoles(ctx context.Context, req *rbac.OverwriteUserRolesReq) (*rbac.OverwriteUserRolesResp, error) {
	var resp rbac.OverwriteUserRolesResp

	if req.UserId == 0 {
		return nil, grpc.NewRPCErrWithMsg(commonerr.ErrCode_ErrCodeInvalidParam, "user_id is required")
	}

	userRoleMod := db.NewUserRoleModel()

	if len(req.UserRoles) == 0 {
		_, err := userRoleMod.DeleteMany(ctx, bson.M{"user_id": req.UserId})
		if err != nil {
			fastlog.Error(err)
			return nil, err
		}

		return &resp, nil
	}

	roleIds, err := elemutil.PluckUint64(req.UserRoles, "RoleId")
	if err != nil {
		fastlog.Error(err)
		return nil, err
	}

	roles, err := db.NewRoleModel().FindAll(ctx, bson.M{"role_id": bson.M{"$in": roleIds}})
	if err != nil {
		fastlog.Error(err)
		return nil, err
	}

	roleMapAny, err := elemutil.KeyBy(roles, "RoleId")
	if err != nil {
		fastlog.Error(err)
		return nil, err
	}

	roleMap := roleMapAny.(map[uint64]*rbac.RoleOrm)

	userRoles, err := userRoleMod.FindAll(ctx, bson.M{"user_id": req.UserId})
	if err != nil {
		fastlog.Error(err)
		return nil, err
	}

	userRoleMapAny, err := elemutil.KeyBy(userRoles, "RoleId")
	if err != nil {
		fastlog.Error(err)
		return nil, err
	}

	userRoleMap := userRoleMapAny.(map[uint64]*rbac.UserRoleOrm)

	var (
		newUserRoles    []*rbac.UserRoleOrm
		existsUserRoles []*rbac.UserRoleOrm
	)
	for _, userRole := range req.UserRoles {
		role, ok := roleMap[userRole.RoleId]
		if !ok {
			continue
		}

		if role.Scope != userRole.Scope {
			return nil, grpc.NewRPCErrWithMsg(commonerr.ErrCode_ErrCodeInvalidParam, "role(name:"+role.Name+") scope mismatch")
		}

		oldUserRole, ok := userRoleMap[userRole.RoleId]
		if !ok {
			newUserRoles = append(newUserRoles, &rbac.UserRoleOrm{
				UserId: req.UserId,
				RoleId: userRole.RoleId,
				Status: userRole.Status,
				Scope:  userRole.Scope,
			})
			continue
		}

		existsUserRoles = append(existsUserRoles, &rbac.UserRoleOrm{
			UserId: req.UserId,
			RoleId: userRole.RoleId,
			Status: userRole.Status,
			Scope:  userRole.Scope,
			ID:     oldUserRole.ID,
		})
	}

	if len(newUserRoles) > 0 {
		err = userRoleMod.InsertMany(ctx, newUserRoles)
		if err != nil {
			fastlog.Error(err)
			return nil, err
		}
	}

	for _, userRole := range existsUserRoles {
		_, err = userRoleMod.Update(ctx, userRole)
		if err != nil {
			fastlog.Error(err)
			return nil, err
		}
	}

	return &resp, nil
}
