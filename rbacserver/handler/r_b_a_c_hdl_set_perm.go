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

func (s *RBAC) SetPerm(ctx context.Context, req *rbac.SetPermReq) (*rbac.SetPermResp, error) {
	var resp rbac.SetPermResp

	if req.Perm == nil {
		return nil, grpc.NewRPCErrWithMsg(rbac.ErrCode_ErrCodeInvalidParam, "perm is empty")
	}

	if req.Perm.Name == "" {
		return nil, grpc.NewRPCErrWithMsg(rbac.ErrCode_ErrCodeInvalidParam, "perm.name is empty")
	}

	if req.Perm.ResourceRoute == "" {
		return nil, grpc.NewRPCErrWithMsg(rbac.ErrCode_ErrCodeInvalidParam, "perm.resource_route is empty")
	}

	var resourceServices []*rbac.ResourceServiceOrm
	for _, resourceService := range req.Perm.ResourceServices {
		resourceServices = append(resourceServices, &rbac.ResourceServiceOrm{
			Service: resourceService.Service,
			Extra:   resourceService.Extra,
		})
	}

	mod := db.NewPermModel()

	if req.Perm.Pid > 0 {
		count, err := mod.FindCount(ctx, bson.M{"perm_id": req.Perm.Pid})
		if err != nil {
			fastlog.Error(err)
			return nil, err
		}

		if count == 0 {
			return nil, grpc.NewRPCErrWithMsg(rbac.ErrCode_ErrCodePermNotFound, "pid does not exist")
		}
	}

	if req.Perm.PermId == 0 {
		allocIdResp, err := idgen.IdGenGRPC().AllocId(ctx, &idgen.AllocIdReq{
			TbName: rbac.PermTbName,
		})
		if err != nil {
			fastlog.Error(err)
			return nil, err
		}

		perm := &rbac.PermOrm{
			PermId:           allocIdResp.Id,
			Name:             req.Perm.Name,
			Scope:            req.Perm.Scope,
			Pid:              req.Perm.Pid,
			ResourceRoute:    req.Perm.ResourceRoute,
			ResourceServices: resourceServices,
			ResourceType:     req.Perm.ResourceType,
		}
		err = mod.InsertOne(ctx, perm)
		if err != nil {
			if mgorm.IsUniqIdxConflictError(err) {
				if err := s.checkAndGetPermConflictErr(ctx, req.Perm.Scope, req.Perm.ResourceRoute, req.Perm.Name); err != nil {
					return nil, err
				}
			}

			fastlog.Error(err)

			return nil, err
		}

		resp.PermId = perm.PermId
		return &resp, nil
	}

	_, err := mod.FindOneByPermId(ctx, req.Perm.PermId)
	if err != nil {
		fastlog.Error(err)
		return nil, err
	}

	perm := &rbac.PermOrm{
		PermId:           req.Perm.PermId,
		Name:             req.Perm.Name,
		Scope:            req.Perm.Scope,
		Pid:              req.Perm.Pid,
		ResourceRoute:    req.Perm.ResourceRoute,
		ResourceServices: resourceServices,
		ResourceType:     req.Perm.ResourceType,
	}

	bm, err := mgorm.ToBsonM(perm)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, grpc.NewRPCErr(rbac.ErrCode_ErrCodePermNotFound)
		}
		fastlog.Error(err)
		return nil, err
	}

	_, err = mod.UpdateOne(ctx, bson.M{"perm_id": req.Perm.PermId}, bm)
	if err != nil {
		if mgorm.IsUniqIdxConflictError(err) {
			if err := s.checkAndGetPermConflictErr(ctx, req.Perm.Scope, req.Perm.ResourceRoute, req.Perm.Name); err != nil {
				return nil, err
			}
		}

		fastlog.Error(err)
		return nil, err
	}

	resp.PermId = req.Perm.PermId

	return &resp, nil
}

func (s *RBAC) checkAndGetPermConflictErr(ctx context.Context, scope, resourceRoute, name string) error {
	conflicts, err := db.NewPermModel().FindAll(ctx, bson.M{
		"scope": scope,
		"$or": []bson.M{
			{
				"resource_route": resourceRoute,
			},
			{
				"name": name,
			},
		},
	})
	if err != nil {
		fastlog.Error(err)
		return err
	}

	for _, conflict := range conflicts {
		if conflict.Name == name {
			return grpc.NewRPCErrWithMsg(rbac.ErrCode_ErrCodeNameExisted, fmt.Sprintf("perm.name:%s is existed", name))
		}

		if conflict.ResourceRoute == resourceRoute {
			return grpc.NewRPCErrWithMsg(rbac.ErrCode_ErrCodeResourceRouteExisted, fmt.Sprintf("perm.resource_route:%s is existed", resourceRoute))
		}
	}

	return nil
}
