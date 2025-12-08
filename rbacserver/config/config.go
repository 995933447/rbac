package config

import (
	"sync"

	"github.com/995933447/easymicro/loader"
)

const ServerConfigFileName = "rbacserver"

type ServerConfig struct {
	SamplePProfTimeLongSec int    `mapstructure:"sample_pprof_time_long_sec"`
	Env                    string `mapstructure:"env"`
	Discovery              string `mapstructure:"discovery"`
	MongoConn              string `mapstructure:"mongo_conn"`
	MongoDb                string `mapstructure:"mongo_db"`
}

func (c *ServerConfig) GetDiscovery() string {
	return c.Discovery
}

func (c *ServerConfig) GetMongoConn() string {
	return c.MongoConn
}

func (c *ServerConfig) GetMongoDb() string {
	return c.MongoDb
}

func (c *ServerConfig) IsDev() bool {
	return c.Env == "dev"
}

func (c *ServerConfig) IsTest() bool {
	return c.Env == "test"
}

func (c *ServerConfig) IsProd() bool {
	return c.Env == "prod"
}

var (
	serverConfig   ServerConfig
	serverConfigMu sync.RWMutex
)

func getServerConfig() *ServerConfig {
	return &serverConfig
}

func SafeReadServerConfig(fn func(c *ServerConfig)) {
	serverConfigMu.RLock()
	defer serverConfigMu.RUnlock()
	fn(getServerConfig())
}

func SafeWriteServerConfig(fn func(c *ServerConfig)) {
	serverConfigMu.Lock()
	defer serverConfigMu.Unlock()
	fn(getServerConfig())
}

func LoadConfig() error {
	var err error
	err = loader.LoadFastlogFromLocal(nil)
	if err != nil {
		return err
	}

	err = loader.LoadAndWatchConfig(ServerConfigFileName, &serverConfig, &serverConfigMu, nil)
	if err != nil {
		return err
	}

	if err = loader.LoadEtcdFromLocal(); err != nil {
		return err
	}

	if err = loader.LoadDiscoveryFromLocal(); err != nil {
		return err
	}

	if err = loader.LoadNatsFromLocal(); err != nil {
		return err
	}

	if err = loader.LoadAndWatchRedisFromLocal(); err != nil {
		return err
	}

	if err = loader.LoadAndWatchMongoFromLocal(); err != nil {
		return err
	}

	return nil
}
