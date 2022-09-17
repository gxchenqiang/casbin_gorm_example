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

	result := checkPerm("user1", "group1", "/api/user", "GET")
	if !result {
		panic("test fail.")
	}
	result = checkPerm("user2", "group2", "/api/data", "POST")
	if !result {
		panic("test fail.")
	}
	result = checkPerm("user1", "group2", "/api/data", "POST")
	if result {
		panic("test fail.")
	}

	//no permission before
	result = checkPerm("user2", "group1", "/api/user", "GET")
	if result {
		panic("test fail.")
	}
	//has permission after add to domain
	group := [][]string{
		{"user2", "Role2", "group1"},
	}
	_, _ = CasbinEnforcer.AddGroupingPolicies(group)
	result = checkPerm("user2", "group1", "/api/user", "GET")
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
	CasbinEnforcer, err = casbin.NewSyncedEnforcer("RBAC_with_domain/rbac_with_domain_model.conf", adapter)
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
		{"Role1", "group1", "/api/user", "GET"},
		{"Role2", "group2", "/api/data", "POST"},
		{"Role2", "group1", "/api/user", "GET"},
	}

	group := [][]string{
		{"user1", "Role1", "group1"},
		{"user2", "Role2", "group2"},
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

func checkPerm(sub, dom, obj, act string) bool {
	result, err := CasbinEnforcer.Enforce(sub, dom, obj, act)
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
