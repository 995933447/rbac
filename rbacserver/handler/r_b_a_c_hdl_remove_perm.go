package handler

import (
	"context"
	"errors"

	"github.com/995933447/easymicro/grpc"
	"github.com/995933447/fastlog"
	"github.com/995933447/rbac/rbac"
	"github.com/995933447/rbac/rbacserver/db"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

func (s *RBAC) RemovePerm(ctx context.Context, req *rbac.RemovePermReq) (*rbac.RemovePermResp, error) {
	var resp rbac.RemovePermResp

	if req.PermId == 0 {
		return nil, grpc.NewRPCErrWithMsg(rbac.ErrCode_ErrCodeInvalidParam, "perm_id is required")
	}

	permMod := db.NewPermModel()
	roleMod := db.NewRoleModel()

	if !req.AutoUnbindRoles {
		count, err := roleMod.FindCount(ctx, bson.M{
			"perm_ids": req.PermId,
		})
		if err != nil {
			fastlog.Errorf("roleModel.FindCount err: %v", err)
			return nil, err
		}

		if count > 0 {
			return nil, grpc.NewRPCErr(rbac.ErrCode_ErrCodePermUsedByRole)
		}
	}

	if !req.AutoRemoveChildren {
		count, err := permMod.FindCount(ctx, bson.M{
			"pid": req.PermId,
		})
		if err != nil {
			fastlog.Error(err)
			return nil, err
		}

		if count > 0 {
			return nil, grpc.NewRPCErr(rbac.ErrCode_ErrCodeForbidRemoveNotLeafPerm)
		}

		_, err = permMod.DeleteOneByPermId(ctx, req.PermId)
		if err != nil {
			fastlog.Error(err)
			return nil, err
		}

		if req.AutoUnbindRoles {
			roleColl, err := roleMod.GetColl()
			if err != nil {
				fastlog.Error(err)
				return nil, err
			}

			_, err = roleColl.UpdateMany(ctx, bson.M{
				"perm_ids": req.PermId,
			}, bson.M{"$pull": bson.M{
				"perm_ids": req.PermId,
			}})
			if err != nil {
				fastlog.Error(err)
				return nil, err
			}
		}

		return &resp, nil
	}

	perm, err := permMod.FindOneByPermId(ctx, req.PermId)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, grpc.NewRPCErr(rbac.ErrCode_ErrCodePermNotFound)
		}

		fastlog.Error(err)
		return nil, err
	}

	perms, err := permMod.FindAllByScope(ctx, perm.Scope, bson.D{})
	if err != nil {
		fastlog.Error(err)
		return nil, err
	}

	mapPid2Perms := make(map[uint64][]*rbac.PermOrm)
	for _, p := range perms {
		children := mapPid2Perms[p.Pid]
		mapPid2Perms[p.Pid] = append(children, p)
	}

	collectChildPermIds := func(id uint64) (childIds []uint64) {
		childPerms := mapPid2Perms[id]
		for _, p := range childPerms {
			childIds = append(childIds, p.PermId)
		}
		return
	}

	autoRemovePermIds := []uint64{req.PermId}
	parentPermIds := []uint64{req.PermId}
	for {
		var allChildPermIds []uint64
		for _, permId := range parentPermIds {
			childPermIds := collectChildPermIds(permId)

			if len(childPermIds) == 0 {
				continue
			}

			autoRemovePermIds = append(autoRemovePermIds, childPermIds...)
			allChildPermIds = append(allChildPermIds, childPermIds...)
		}

		if len(allChildPermIds) == 0 {
			break
		}

		parentPermIds = allChildPermIds
	}

	_, err = permMod.DeleteMany(ctx, bson.M{
		"perm_id": bson.M{
			"$in": autoRemovePermIds,
		},
	})
	if err != nil {
		fastlog.Error(err)
		return nil, err
	}

	if req.AutoUnbindRoles {
		roleColl, err := roleMod.GetColl()
		if err != nil {
			fastlog.Error(err)
			return nil, err
		}

		_, err = roleColl.UpdateMany(ctx, bson.M{
			"perm_ids": bson.M{
				"$in": autoRemovePermIds,
			},
		}, bson.M{"$pull": bson.M{
			"perm_ids": bson.M{
				"$in": autoRemovePermIds,
			},
		}})
		if err != nil {
			fastlog.Error(err)
			return nil, err
		}
	}

	return &resp, nil
}
