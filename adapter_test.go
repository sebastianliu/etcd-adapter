package etcdadapter

import (
	"testing"

	"github.com/batchcorp/casbin/v2"
	"github.com/batchcorp/casbin/v2/util"
)

func testGetPolicy(t *testing.T, e *casbin.Enforcer, res [][]string) {
	t.Helper()
	myRes := e.GetPolicy()

	if !util.Array2DEquals(res, myRes) {
		t.Error("Test failed, Policy: ", myRes, ", supposed to be ", res)
		return
	}

	t.Log("Test pass")
}

func initPolicy(t *testing.T, pathKey string, etcdEndpoints []string, authConfig *AuthConfig) {
	// Because the ETCD is empty at first,
	// so we need to load the policy from the file adapter (.CSV) first.
	e, _ := casbin.NewEnforcer("examples/rbac_model.conf", "examples/rbac_policy.csv")

	a, _ := NewAdapter(etcdEndpoints, pathKey, authConfig)
	// This is a trick to save the current policy to the ETCD.
	// We can't call e.SavePolicy() because the adapter in the enforcer is still the file adapter.
	// The current policy means the policy in the Casbin enforcer (aka in memory).
	err := a.SavePolicy(e.GetModel())
	if err != nil {
		panic(err)
	}

	// Clear the current policy.
	e.ClearPolicy()
	testGetPolicy(t, e, [][]string{})

	// Load the policy from ETCD.
	err = a.LoadPolicy(e.GetModel())
	if err != nil {
		panic(err)
	}
	testGetPolicy(t, e, [][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}})
}

func testSaveLoad(t *testing.T, pathKey string, etcdEndpoints []string, authConfig *AuthConfig) {
	// Initialize some policy in ETCD.
	initPolicy(t, pathKey, etcdEndpoints, authConfig)
	// Note: you don't need to look at the above code
	// if you already have a working ETCD with policy inside.

	// Now the ETCD has policy, so we can provide a normal use case.
	// Create an adapter and an enforcer.
	// NewEnforcer() will load the policy automatically.
	a, _ := NewAdapter(etcdEndpoints, pathKey, authConfig)
	e, _ := casbin.NewEnforcer("examples/rbac_model.conf", a)
	testGetPolicy(t, e, [][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}})
}

func testAutoSave(t *testing.T, pathKey string, etcdEndpoints []string, authConfig *AuthConfig) {
	// Initialize some policy in ETCD.
	initPolicy(t, pathKey, etcdEndpoints, authConfig)
	// Note: you don't need to look at the above code
	// if you already have a working ETCD with policy inside.

	// Now the ETCD has policy, so we can provide a normal use case.
	// Create an adapter and an enforcer.
	// NewEnforcer() will load the policy automatically.
	a, _ := NewAdapter(etcdEndpoints, pathKey, authConfig)
	e, _ := casbin.NewEnforcer("examples/rbac_model.conf", a)

	// AutoSave is enabled by default.
	// Now we disable it.
	e.EnableAutoSave(false)

	// Because AutoSave is disabled, the policy change only affects the policy in Casbin enforcer,
	// it doesn't affect the policy in the storage.
	e.AddPolicy("alice", "data1", "write")
	// Reload the policy from the storage to see the effect.
	e.LoadPolicy()
	// This is still the original policy.
	testGetPolicy(t, e, [][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}})

	// Now we enable the AutoSave.
	e.EnableAutoSave(true)

	// Because AutoSave is enabled, the policy change not only affects the policy in Casbin enforcer,
	// but also affects the policy in the storage.
	e.AddPolicy("alice", "data1", "write")
	// Reload the policy from the storage to see the effect.
	e.LoadPolicy()
	// The policy has a new rule: {"alice", "data1", "write"}.
	testGetPolicy(t, e, [][]string{{"alice", "data1", "read"}, {"alice", "data1", "write"}, {"bob", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}})

	// Remove the added rule.
	e.RemovePolicy("alice", "data1", "write")
	e.LoadPolicy()
	testGetPolicy(t, e, [][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}})

	// Remove "data2_admin" related policy rules via a filter.
	// Two rules: {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"} will be deleted.
	e.RemoveFilteredPolicy(0, "data2_admin")
	e.LoadPolicy()
	testGetPolicy(t, e, [][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}})

}

func TestAdapters(t *testing.T) {
	testSaveLoad(t, "casbin_policy_test", []string{"http://127.0.0.1:2379"}, nil)
	testAutoSave(t, "casbin_policy_test", []string{"http://127.0.0.1:2379"}, nil)

	// Uncomment to perform a tls test

	//authConfig := &AuthConfig{
	//	UseTLS: true,
	//	CACert: `fill this in`,
	//	ClientKey: `fill this in`,
	//	ClientCert: `fill this in`,
	//}
	//
	//testSaveLoad(t, "casbin_policy_test", []string{"https://etcd-1.sfo3.dev.batch.sh:2379"}, authConfig)
	//testAutoSave(t, "casbin_policy_test", []string{"https://etcd-1.sfo3.dev.batch.sh:2379"}, authConfig)

}
