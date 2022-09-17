package main

import (
	"fmt"
	"github.com/casbin/casbin/v2"
	gormadapter "github.com/casbin/gorm-adapter/v3"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"log"
)

var CasbinEnforcer *casbin.SyncedEnforcer

func main() {
	if err := initCasbin(); err != nil {
		log.Fatal("casbin init fail:", err.Error())
	}

	type Attr struct {
		Owner string
	}

	result := checkPerm("user1", Attr{Owner: "user1"})
	if !result {
		panic("test fail.")
	}
	result = checkPerm("user2", Attr{Owner: "user2"})
	if !result {
		panic("test fail.")
	}
	result = checkPerm("user2", Attr{Owner: "user1"})
	if result {
		panic("test fail.")
	}
	log.Println("===== test success =====")
}

func initCasbin() error {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}

	adapter, err := gormadapter.NewAdapterByDBWithCustomTable(db, &CasbinRule{})
	if err != nil {
		return err
	}
	CasbinEnforcer, err = casbin.NewSyncedEnforcer("ABAC/abac_model.conf", adapter)
	if err != nil {
		return err
	}
	err = CasbinEnforcer.LoadPolicy()
	if err != nil {
		return err
	}
	return nil
}

func checkPerm(sub string, obj interface{}) bool {
	result, err := CasbinEnforcer.Enforce(sub, obj, "")
	if err != nil {
		fmt.Println("casbin check err:", err.Error())
		return false
	}
	return result
}

type CasbinRule struct {
	PType string `gorm:"column:ptype"`
	V0    string `gorm:"column:v0"`
	V1    string `gorm:"column:v1"`
	V2    string `gorm:"column:v2"`
	V3    string `gorm:"column:v3"`
	V4    string `gorm:"column:v4"`
	V5    string `gorm:"column:v5"`
	ID    int    `gorm:"column:id"`
}
