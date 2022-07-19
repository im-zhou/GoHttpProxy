package pkg

import (
	"github.com/go-redis/redis"
)

// Rdb 声明一个全局的rdb变量
var Rdb *redis.Client

// InitClient 初始化连接
func InitClient() (err error) {
	Rdb = redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "", // no password set
		DB:       0,  // use default DB
	})
	_, err = Rdb.Ping().Result()
	if err != nil {
		return err
	}
	return nil
}
