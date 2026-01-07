package util

import "github.com/995933447/rbac/rbac"

func GenIdGenTbName(dbName, tbName string) string {
	return rbac.EasymicroGRPCPbServiceNameRBAC + ":" + dbName + "." + tbName + "."
}
