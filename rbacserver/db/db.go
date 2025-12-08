package db

import (
	"github.com/995933447/rbac/rbac"
	"github.com/995933447/rbac/rbacserver/config"
)

func NewUserRoleModel() *rbac.UserRoleModel {
	mod := rbac.NewUserRoleModel()
	config.SafeReadServerConfig(func(c *config.ServerConfig) {
		if conn := c.GetMongoConn(); conn != "" {
			mod.SetConn(conn)
		}
		if db := c.GetMongoDb(); db != "" {
			mod.SetDb(db)
		}
	})
	return mod
}

func NewRoleModel() *rbac.RoleModel {
	mod := rbac.NewRoleModel()
	config.SafeReadServerConfig(func(c *config.ServerConfig) {
		if conn := c.GetMongoConn(); conn != "" {
			mod.SetConn(conn)
		}
		if db := c.GetMongoDb(); db != "" {
			mod.SetDb(db)
		}
	})
	return mod
}

func NewPermModel() *rbac.PermModel {
	mod := rbac.NewPermModel()
	config.SafeReadServerConfig(func(c *config.ServerConfig) {
		if conn := c.GetMongoConn(); conn != "" {
			mod.SetConn(conn)
		}
		if db := c.GetMongoDb(); db != "" {
			mod.SetDb(db)
		}
	})
	return mod
}
