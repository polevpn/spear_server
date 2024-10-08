package main

import (
	"errors"
	"strconv"
	"sync"
	"time"

	"github.com/polevpn/anyvalue"
)

const (
	TOKEN_EXPIRE_PERIOD   = 86400
	TOKEN_CLEAN_UP_PERIOD = 5
)

type User struct {
	Uid           uint64
	Email         string
	Vip           int
	VipExpireTime uint64
	LastLoginTime uint64
}

type TokenInfo struct {
	user       string
	expireTime int64
}

type LocalLoginChecker struct {
	mutex  *sync.RWMutex
	tokens map[string]*TokenInfo
}

func NewLocalLoginChecker() *LocalLoginChecker {

	llc := &LocalLoginChecker{tokens: make(map[string]*TokenInfo), mutex: &sync.RWMutex{}}

	go func() {

		timer := time.NewTicker(time.Second * TOKEN_CLEAN_UP_PERIOD)

		for range timer.C {
			llc.cleanToken()
		}
	}()

	return llc
}

func (llc *LocalLoginChecker) CheckToken(user string, token string) bool {

	llc.mutex.RLock()
	defer llc.mutex.RUnlock()

	tokenInfo := llc.tokens[token]

	if tokenInfo != nil {
		return time.Now().Unix() < tokenInfo.expireTime
	}

	return false
}

func (llc *LocalLoginChecker) Auth(user string, pwd string) (*anyvalue.AnyValue, error) {

	users := Config.Get("auth.local.users").AsArray()

	for _, u := range users {
		u, ok := u.(map[string]interface{})
		if ok {
			if u["user"].(string) == user && u["pwd"].(string) == pwd {

				llc.mutex.Lock()
				defer llc.mutex.Unlock()

				token := Md5(strconv.FormatInt(time.Now().UnixNano(), 10))
				llc.tokens[token] = &TokenInfo{user: user, expireTime: time.Now().Unix() + TOKEN_EXPIRE_PERIOD}
				av := anyvalue.New()
				av.Set("token", token)
				return av, nil
			}
		}
	}
	return nil, errors.New("invalid user or pwd")
}

func (llc *LocalLoginChecker) cleanToken() {

	llc.mutex.Lock()
	defer llc.mutex.Unlock()

	tokenList := make([]string, 0)

	for token, tokenInfo := range llc.tokens {
		now := time.Now().Unix()
		if tokenInfo.expireTime < now {
			tokenList = append(tokenList, token)
		}
	}

	for _, token := range tokenList {
		delete(llc.tokens, token)
	}
}
