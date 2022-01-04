package main

import (
	"log"

	"github.com/batchcorp/etcd-adapter"
	"github.com/casbin/casbin/v2"
)

func main() {
	// Initialize a casbin etcd adapter and use it in a Casbin enforcer:
	// The adapter will use the ETCD and a named path with the key you give.
	// If not provided, the adapter will use the default value casbin_policy.
	a, err := etcdadapter.NewAdapter([]string{"http://127.0.0.1:2379"}, "casbin_policy_test", nil)
	if err != nil {
		log.Fatalf("Error: %s\n", err)
	}

	e, err := casbin.NewEnforcer("rbac_model.conf", a)
	if err != nil {
		log.Fatalf("Error: %s\n", err)
	}

	// Load the policy from ETCD.
	if err := e.LoadPolicy(); err != nil {
		log.Fatalf("Error: %s\n", err)
	}

	// Check the permission.
	if _, err := e.Enforce("alice", "data1", "read"); err != nil {
		log.Fatalf("Error: %s\n", err)
	}

	// Modify the policy.
	// e.AddPolicy(...)
	// e.RemovePolicy(...)

	// Save the policy back to DB.
	if err := e.SavePolicy(); err != nil {
		log.Fatalf("Error: %s\n", err)
	}
}
