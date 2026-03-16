package openconnect

import (
	"encoding/hex"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/fisker/zvpn/internal/database"
	"github.com/fisker/zvpn/models"
	"github.com/gin-gonic/gin"
)

func (h *Handler) AuthMiddleware(c *gin.Context) {

	if c.Request.URL.Path == "/" || c.Request.URL.Path == "/auth" ||
		c.Request.URL.Path == "/profile.xml" {
		c.Next()
		return
	}

	if c.GetBool("authenticated") {
		c.Next()
		return
	}

	sessionCookie, cookieErr := c.Cookie("webvpn")
	if cookieErr != nil || sessionCookie == "" {
		log.Printf("OpenConnect: AuthMiddleware - No webvpn cookie found (Path: %s, Error: %v, All cookies: %v)",
			c.Request.URL.Path, cookieErr, c.Request.Cookies())
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	log.Printf("OpenConnect: AuthMiddleware - Found webvpn cookie: %s (Path: %s, Cookie length: %d)",
		sessionCookie, c.Request.URL.Path, len(sessionCookie))
	log.Printf("OpenConnect: AuthMiddleware - All cookies: %v", c.Request.Cookies())

	var user models.User
	var userID uint
	foundByToken := false

	if len(sessionCookie) == 32 {

		sessionCookieUpper := strings.ToUpper(sessionCookie)
		if _, err := hex.DecodeString(sessionCookieUpper); err == nil {

			var session models.Session
			if err := database.DB.Where("token = ? AND active = ? AND expires_at > ?",
				sessionCookieUpper, true, time.Now()).First(&session).Error; err != nil {
				log.Printf("OpenConnect: AuthMiddleware - Session not found or expired (token: %s...): %v", sessionCookieUpper[:16], err)

				foundByToken = false
			} else {

				userID = session.UserID
				foundByToken = true
				log.Printf("OpenConnect: AuthMiddleware - Token validated successfully (token: %s..., userID: %d)", sessionCookieUpper[:16], userID)
			}
		}
	}

	if !foundByToken {

		parts := strings.Split(sessionCookie, "-")
		var parseErr error

		if len(parts) == 3 {

			var uid int
			uid, parseErr = strconv.Atoi(parts[2])
			if parseErr != nil {
				log.Printf("OpenConnect: AuthMiddleware - Failed to parse userID from cookie: %s, error: %v", sessionCookie, parseErr)
				c.AbortWithStatus(http.StatusUnauthorized)
				return
			}
			userID = uint(uid)
			log.Printf("OpenConnect: AuthMiddleware - Using legacy cookie format (webvpn-username-userID): %s", sessionCookie)
		} else if len(parts) == 2 {

			var uid int
			uid, parseErr = strconv.Atoi(parts[1])
			if parseErr != nil {
				log.Printf("OpenConnect: AuthMiddleware - Failed to parse userID from legacy cookie: %s, error: %v", sessionCookie, parseErr)
				c.AbortWithStatus(http.StatusUnauthorized)
				return
			}
			userID = uint(uid)
			log.Printf("OpenConnect: AuthMiddleware - Using legacy cookie format (username-userID): %s", sessionCookie)
		} else {
			log.Printf("OpenConnect: AuthMiddleware - Invalid cookie format: %s (expected token or webvpn-username-userID or username-userID, got %d parts)",
				sessionCookie, len(parts))
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
	}

	if err := database.DB.First(&user, userID).Error; err != nil {
		log.Printf("OpenConnect: AuthMiddleware - User not found (userID: %d): %v", userID, err)
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	if !user.IsActive {
		c.AbortWithStatus(http.StatusForbidden)
		return
	}

	c.Set("authenticated", true)
	c.Set("userID", userID)
	c.Set("username", user.Username)
	c.Set("vpnIP", user.VPNIP)

	c.Next()
}

func (h *Handler) ConnectMiddleware(c *gin.Context) {
	if !c.GetBool("authenticated") {
		log.Printf("OpenConnect: Unauthenticated connection attempt")
		c.AbortWithStatus(http.StatusForbidden)
		return
	}

	userID, exists := c.Get("userID")
	if !exists {
		log.Printf("OpenConnect: Cannot get userID")
		c.AbortWithStatus(http.StatusForbidden)
		return
	}

	var user models.User
	if err := database.DB.Preload("Groups.Policies.Routes").Preload("Groups.Policies.ExcludeRoutes").First(&user, userID).Error; err != nil {
		log.Printf("OpenConnect: Failed to get user info: %v", err)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	c.Set("user", user)

	c.Next()
}

