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
	if err := addPolicies(); err != nil {
		log.Fatal("add policy fail:", err.Error())
	}

	type Attr struct {
		Age  int
		Time int
	}
	result := checkPerm("user1", "group1", "/api/user", "GET", Attr{Age: 18})
	if !result {
		panic("test fail.")
	}
	result = checkPerm("user1", "group1", "/api/user", "GET", Attr{Age: 17})
	if result {
		panic("test fail.")
	}
	result = checkPerm("user2", "group2", "/api/data", "POST", Attr{Time: 10})
	if !result {
		panic("test fail.")
	}

	//no permission before
	result = checkPerm("user1", "group2", "/api/data", "POST", Attr{Time: 17})
	if result {
		panic("test fail.")
	}
	//has permission after add policy
	policies := [][]string{
		{"Role1", "group2", "/api/data", "POST", "r.attr.Time > 9 && r.attr.Time < 18"},
	}
	_, _ = CasbinEnforcer.AddPolicies(policies)
	result = checkPerm("user1", "group2", "/api/data", "POST", Attr{Time: 17})
	if !result {
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
	CasbinEnforcer, err = casbin.NewSyncedEnforcer("RBAC_mixed_ABAC/rbac_mixed_abac_model.conf", adapter)
	if err != nil {
		return err
	}
	err = CasbinEnforcer.LoadPolicy()
	if err != nil {
		return err
	}
	return nil
}

func addPolicies() error {
	policies := [][]string{
		{"Role1", "group1", "/api/user", "GET", "r.attr.Age > 17 && r.attr.Age < 60"},
		{"Role2", "group2", "/api/data", "POST", "r.attr.Time > 9 && r.attr.Time < 18"},
	}

	group := [][]string{
		{"user1", "Role1"},
		{"user2", "Role2"},
	}

	_, err := CasbinEnforcer.AddPolicies(policies)
	if err != nil {
		fmt.Println("add polices fail, err:", err.Error())
		return err
	}
	_, err = CasbinEnforcer.AddGroupingPolicies(group)
	if err != nil {
		fmt.Println("add group polices fail, err:", err.Error())
		return err
	}
	return nil
}

func checkPerm(sub, dom, obj, act string, attr interface{}) bool {
	result, err := CasbinEnforcer.Enforce(sub, dom, obj, act, attr)
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
