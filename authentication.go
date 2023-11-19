/*
	Create a Gin-Gonic middleware for oauth2 authentication
	Use Redis as a cache in which store an oauth2 authentication for 1 hour
	Insert in gin.Context user_id (*DataReceive)
	Insert in gin.Context user_roles ([]string)
*/

package oauth2

import (
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	"net/http"
)

type JwtInfo struct {
	Aud                string   `json:"aud"`
	Exp                int      `json:"exp"`
	Iat                int      `json:"iat"`
	Iss                string   `json:"iss"`
	Sub                string   `json:"sub"`
	Jti                string   `json:"jti"`
	AuthenticationType string   `json:"authenticationType"`
	Email              string   `json:"email"`
	EmailVerified      bool     `json:"email_verified"`
	PreferredUsername  string   `json:"preferred_username"`
	ApplicationID      string   `json:"applicationId"`
	Roles              []string `json:"roles"`
	Sid                string   `json:"sid"`
	AuthTime           int      `json:"auth_time"`
	Tid                string   `json:"tid"`
	State              string   `json:"state"`
	jwt.StandardClaims
}

/*
Gin-Gonic middleware to import for oauth2 authentication
*/
func Authentication(c *gin.Context) {
	auth := c.GetHeader("Authorization")
	if len(auth) > 8 {
		auth = auth[7:]
		isValid, jwtInfo := isJwtValid(auth, []byte(MasterKey))
		if isValid {
			c.Set("user_info", *jwtInfo)
			c.Set("user_roles", jwtInfo.Roles)
			c.Set("application_id", jwtInfo.Aud)
			c.Next()
		} else {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{})
		}
	} else {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{})
	}
}

func isJwtValid(tokenString string, secretKey []byte) (bool, *JwtInfo) {
	token, err := jwt.ParseWithClaims(tokenString, &JwtInfo{}, func(token *jwt.Token) (interface{}, error) {
		return secretKey, nil
	})
	if err != nil {
		return false, nil
	}
	jwtInfo, _ := token.Claims.(*JwtInfo)
	return token.Valid, jwtInfo
}

func Application(applicationId string) func(c *gin.Context) {
	return func(c *gin.Context) {
		applicationIdToken := c.MustGet("application_id").(string)
		if applicationId == applicationIdToken {
			c.Next()
		} else {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{})
		}
	}
}

/*
Gin-Gonic middleware to import for check roles of an user
it MUST be used after Authentication
*/
func Roles(roles []string) func(c *gin.Context) {
	return func(c *gin.Context) {
		var rolesUser []string
		canContinue := false
		rolesUser = c.MustGet("user_roles").([]string)
		for _, role := range roles {
			if isInArray(role, rolesUser) {
				canContinue = true
				break
			}
		}
		if canContinue {
			c.Next()
		} else {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{})
		}
	}
}

func State(states []string) func(c *gin.Context) {
	return func(c *gin.Context) {
		canContinue := false
		jwtInfo := c.MustGet("user_info").(JwtInfo)
		for _, state := range states {
			if state == jwtInfo.State {
				canContinue = true
				break
			}
		}
		if canContinue {
			c.Next()
		} else {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{})
		}
	}
}

/*
Simple function to check if a value is in an array
*/
func isInArray(value string, arrayValues []string) bool {
	for _, arrayValue := range arrayValues {
		if value == arrayValue {
			return true
		}
	}
	return false
}
