etcd-adapter
====

[![Build Status](https://travis-ci.org/sebastianliu/etcd-adapter.svg?branch=master)](https://travis-ci.org/sebastianliu/etcd-adapter)
[![Coverage Status](https://coveralls.io/repos/github/sebastianliu/etcd-adapter/badge.svg)](https://coveralls.io/github/sebastianliu/etcd-adapter)
[![Godoc](https://godoc.org/github.com/sebastianliu/etcd-adapter?status.svg)](https://godoc.org/github.com/sebastianliu/etcd-adapter)

## Update 12.27.2021

This is an updated version of the `etcd-adapter` written by @sebastianliu.

This version has a few quality of life updates:

1. Updated to use `go mod`
2. Use "go.etcd.io/etcd/client/v3" instead of the github pkg
3. Use casbin/v2 (as v1 casbin panic's instead of returning errors)
4. Updated lib to no longer panic on bad instantiation
5. Support etcd auth 

## Overview

ETCD adapter is the policy storage adapter for [Casbin](https://github.com/casbin/casbin). With this library, Casbin can load policy from ETCD and save policy to it. ETCD adapter support the __Auto-Save__ feature for Casbin policy. This means it can support adding a single policy rule to the storage, or removing a single policy rule from the storage.

## Installation
```bash
go get github.com/batchcorp/etcd-adapter
```

## Auth

If your etcd is setup with TLS and/or username/pass auth, you can pass an
optional `AuthConfig`.

## Example
```go
package main

import (
	"github.com/batchcorp/etcd-adapter"
	"github.com/casbin/casbin/v2"
)

func main() {
	// Initialize a casbin etcd adapter and use it in a Casbin enforcer:
	// The adapter will use the ETCD and a named path with the key you give.
	// If not provided, the adapter will try to use the default value casbin_policy.
	// If you have namespace to distinguish keys in your etcd, you can use your_namespace/casbin_root_path
	a, _ := etcdadapter.NewAdapter([]string{"http://127.0.0.1:2379"}, "casbin_policy_test", nil) // Your etcd endpoints and the path key.

	e, _ := casbin.NewEnforcer("rbac_model.conf", a)

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
