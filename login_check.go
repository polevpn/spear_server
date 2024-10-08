package main

import "github.com/polevpn/anyvalue"

type LoginChecker interface {
	Auth(user string, pwd string) (*anyvalue.AnyValue, error)
	CheckToken(user string, token string) bool
}
