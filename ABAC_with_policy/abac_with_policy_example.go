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

	type User struct {
		Age  int
		Time int
	}

	result := checkPerm(User{Age: 18}, "/api/user", "GET")
	if !result {
		panic("test fail.")
	}
	result = checkPerm(User{Age: 17}, "/api/user", "GET")
	if result {
		panic("test fail.")
	}
	result = checkPerm(User{Time: 10}, "/api/data", "POST")
	if !result {
		panic("test fail.")
	}
	result = checkPerm(User{Time: 21}, "/api/data", "POST")
	if result {
		panic("test fail.")
	}
	result = checkPerm(User{Age: 21}, "/api/data", "POST")
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
	CasbinEnforcer, err = casbin.NewSyncedEnforcer("ABAC_with_policy/abac_with_policy_model.conf", adapter)
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
		{"r.user.Age > 17 && r.user.Age < 60", "/api/user", "GET"},
		{"r.user.Time > 9 && r.user.Time < 18", "/api/data", "POST"},
	}

	_, err := CasbinEnforcer.AddPolicies(policies)
	if err != nil {
		fmt.Println("add polices fail, err:", err.Error())
		return err
	}
	return nil
}

func checkPerm(user interface{}, obj string, act string) bool {
	result, err := CasbinEnforcer.Enforce(user, obj, act)
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
