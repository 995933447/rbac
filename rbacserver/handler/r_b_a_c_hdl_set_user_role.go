package handler

import (
	"context"
	"errors"

	"github.com/995933447/easymicro/grpc"
	"github.com/995933447/fastlog"
	"github.com/995933447/mgorm"
	"github.com/995933447/rbac/rbac"
	"github.com/995933447/rbac/rbacserver/db"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

func (s *RBAC) SetUserRole(ctx context.Context, req *rbac.SetUserRoleReq) (*rbac.SetUserRoleResp, error) {
	var resp rbac.SetUserRoleResp

	if req.UserRole == nil {
		return nil, grpc.NewRPCErrWithMsg(rbac.ErrCode_ErrCodeInvalidParam, "user_role is required")
	}

	if req.UserRole.UserId == 0 {
		return nil, grpc.NewRPCErrWithMsg(rbac.ErrCode_ErrCodeInvalidParam, "user_role.user_id is required")
	}

	if req.UserRole.RoleId == 0 {
		return nil, grpc.NewRPCErrWithMsg(rbac.ErrCode_ErrCodeInvalidParam, "user_role.role_id is required")
	}

	if req.UserRole.Status == 0 {
		return nil, grpc.NewRPCErrWithMsg(rbac.ErrCode_ErrCodeInvalidParam, "user_role.status is empty")
	}

	role, err := db.NewRoleModel().FindOneByRoleId(ctx, req.UserRole.RoleId)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, grpc.NewRPCErr(rbac.ErrCode_ErrCodeRoleNotFound)
		}
	}

	if role.Scope != req.UserRole.Scope {
		return nil, grpc.NewRPCErrWithMsg(rbac.ErrCode_ErrCodeInvalidParam, "user_role.scope must match scope")
	}

	mod := db.NewUserRoleModel()

	userRole := &rbac.UserRoleOrm{
		UserId: req.UserRole.UserId,
		RoleId: req.UserRole.RoleId,
		Status: req.UserRole.Status,
		Scope:  req.UserRole.Scope,
	}

	oldUserRole, err := mod.FindOneByUserIdAndRoleId(ctx, req.UserRole.UserId, req.UserRole.RoleId)
	if err != nil {
		if !errors.Is(err, mongo.ErrNoDocuments) {
			fastlog.Error(err)
			return nil, err
		}

		if req.Id == "" {
			err = mod.InsertOne(ctx, userRole)
			if err != nil {
				fastlog.Error(err)
				return nil, err
			}

			resp.Id = userRole.ID.Hex()

			return &resp, nil
		}
	}

	if oldUserRole.ID.Hex() != req.Id {
		return nil, grpc.NewRPCErr(rbac.ErrCode_ErrCodeUserRoleExisted)
	}

	objId, err := primitive.ObjectIDFromHex(req.Id)
	if err != nil {
		fastlog.Error(err)
		return nil, err
	}

	bm, err := mgorm.ToBsonM(userRole)
	if err != nil {
		fastlog.Error(err)
		return nil, err
	}

	_, err = mod.UpdateOne(ctx, bson.M{"_id": objId}, bm)
	if err != nil {
		fastlog.Error(err)
		return nil, err
	}

	resp.Id = objId.Hex()

	return &resp, nil
}
