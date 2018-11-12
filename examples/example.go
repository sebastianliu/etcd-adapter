package main

import (
	"github.com/casbin/casbin"
	"github.com/sebastianliu/etcd-adapter"
)

func main() {
	// Initialize a casbin etcd adapter and use it in a Casbin enforcer:
	// The adapter will use the ETCD and a named path with the key you give.
	// If not provided, the adapter will use the default value casbin_policy.
	a := etcdadapter.NewAdapter([]string{"http://127.0.0.1:2379"}, "casbin_policy_test") // Your etcd endpoints and the path key.

	e := casbin.NewEnforcer("rbac_model.conf", a)

	// Load the policy from ETCD.
	e.LoadPolicy()

	// Check the permission.
	e.Enforce("alice", "data1", "read")

	// Modify the policy.
	// e.AddPolicy(...)
	// e.RemovePolicy(...)

	// Save the policy back to DB.
	e.SavePolicy()
}
