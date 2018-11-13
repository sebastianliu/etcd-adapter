etcd-adapter
====

[![Build Status](https://travis-ci.org/sebastianliu/etcd-adapter.svg?branch=master)](https://travis-ci.org/sebastianliu/etcd-adapter)
[![Coverage Status](https://coveralls.io/repos/github/sebastianliu/etcd-adapter/badge.svg)](https://coveralls.io/github/sebastianliu/etcd-adapter)
[![Godoc](https://godoc.org/github.com/sebastianliu/etcd-adapter?status.svg)](https://godoc.org/github.com/sebastianliu/etcd-adapter)

ETCD adapter is the policy storage adapter for [Casbin](https://github.com/casbin/casbin). With this library, Casbin can load policy from ETCD and save policy to it. ETCD adapter support the __Auto-Save__ feature for Casbin policy. This means it can support adding a single policy rule to the storage, or removing a single policy rule from the storage.

## Installation
```bash
go get github.com/sebastianliu/etcd-adapter
```

## Sample Example
```go
package main

import (
	"github.com/sebastianliu/etcd-adapter"
	"github.com/casbin/casbin"
)

func main() {
	// Initialize a casbin etcd adapter and use it in a Casbin enforcer:
	// The adapter will use the ETCD and a named path with the key you give.
	// If not provided, the adapter will try to use the default value casbin_policy.
	// If you have namespace to distinguish keys in your etcd, you can use your_namespace/casbin_root_path
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
```
