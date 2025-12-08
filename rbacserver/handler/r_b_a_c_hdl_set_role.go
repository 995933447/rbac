package handler

import (
	"context"
	"errors"
	"fmt"

	"github.com/995933447/easymicro/grpc"
	"github.com/995933447/fastlog"
	"github.com/995933447/idgen/idgen"
	"github.com/995933447/mgorm"
	"github.com/995933447/rbac/rbac"
	"github.com/995933447/rbac/rbacserver/db"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

func (s *RBAC) SetRole(ctx context.Context, req *rbac.SetRoleReq) (*rbac.SetRoleResp, error) {
	var resp rbac.SetRoleResp

	if req.Role == nil {
		return nil, grpc.NewRPCErrWithMsg(rbac.ErrCode_ErrCodeInvalidParam, "role is empty")
	}

	if req.Role.Name == "" {
		return nil, grpc.NewRPCErrWithMsg(rbac.ErrCode_ErrCodeInvalidParam, "role.name is empty")
	}

	if req.Role.Status == 0 {
		return nil, grpc.NewRPCErrWithMsg(rbac.ErrCode_ErrCodeInvalidParam, "role.status is empty")
	}

	permNum := len(req.Role.PermIds)
	if permNum > 0 {
		perms, err := db.NewPermModel().FindAll(ctx, bson.M{"perm_id": bson.M{"$in": req.Role.PermIds}, "scope": req.Role.Scope})
		if err != nil {
			return nil, err
		}

		if len(perms) != permNum {
			permSet := make(map[uint64]struct{})
			for _, perm := range perms {
				permSet[perm.PermId] = struct{}{}
			}

			for _, permId := range req.Role.PermIds {
				if _, ok := permSet[permId]; !ok {
					return nil, grpc.NewRPCErrWithMsg(rbac.ErrCode_ErrCodePermNotFound, fmt.Sprintf("perm(id:%d) does not exist", permId))
				}
			}
		}
	}

	mod := db.NewRoleModel()
	if req.Role.RoleId == 0 {
		allocIdResp, err := idgen.IdGenGRPC().AllocId(ctx, &idgen.AllocIdReq{
			TbName: rbac.RoleTbName,
		})
		if err != nil {
			fastlog.Error(err)
			return nil, err
		}

		role := &rbac.RoleOrm{
			Name:         req.Role.Name,
			Scope:        req.Role.Scope,
			Status:       req.Role.Status,
			PermIds:      req.Role.PermIds,
			RoleId:       allocIdResp.Id,
			Remark:       req.Role.Remark,
			IsSuperAdmin: req.Role.IsSuperAdmin,
		}
		err = mod.InsertOne(ctx, role)
		if err != nil {
			if mgorm.IsUniqIdxConflictError(err) {
				if err := s.checkAndGetRoleConflictErr(ctx, req.Role.Scope, req.Role.Name); err != nil {
					return nil, err
				}
			}

			fastlog.Error(err)

			return nil, err
		}

		resp.RoleId = role.RoleId
		return &resp, nil
	}

	_, err := mod.FindOneByRoleId(ctx, req.Role.RoleId)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, grpc.NewRPCErr(rbac.ErrCode_ErrCodeRoleNotFound)
		}

		fastlog.Error(err)
		return nil, err
	}

	perm := &rbac.RoleOrm{
		Name:         req.Role.Name,
		Scope:        req.Role.Scope,
		Status:       req.Role.Status,
		PermIds:      req.Role.PermIds,
		Remark:       req.Role.Remark,
		RoleId:       req.Role.RoleId,
		IsSuperAdmin: req.Role.IsSuperAdmin,
	}

	bm, err := mgorm.ToBsonM(perm)
	if err != nil {
		fastlog.Error(err)
		return nil, err
	}

	_, err = mod.UpdateOne(ctx, bson.M{"role_id": req.Role.RoleId}, bm)
	if err != nil {
		if mgorm.IsUniqIdxConflictError(err) {
			if err := s.checkAndGetRoleConflictErr(ctx, req.Role.Scope, req.Role.Name); err != nil {
				return nil, err
			}
		}

		fastlog.Error(err)
		return nil, err
	}

	resp.RoleId = req.Role.RoleId

	return &resp, nil
}

func (s *RBAC) checkAndGetRoleConflictErr(ctx context.Context, scope, name string) error {
	count, err := db.NewRoleModel().FindCount(ctx, bson.M{
		"scope": scope,
		"name":  name,
	})
	if err != nil {
		fastlog.Error(err)
		return err
	}

	if count > 0 {
		return grpc.NewRPCErrWithMsg(rbac.ErrCode_ErrCodeNameExisted, fmt.Sprintf("role.name:%s is existed", name))
	}

	return nil
}
