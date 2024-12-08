package main

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Jcastel2014/test3/internal/data"
	"github.com/Jcastel2014/test3/internal/validator"
	"golang.org/x/time/rate"
)

func (a *appDependencies) recoverPanic(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			err := recover()
			if err != nil {
				w.Header().Set("Connection", "close")
				a.serverErrResponse(w, r, fmt.Errorf("%s", err))
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func (a *appDependencies) rateLimit(next http.Handler) http.Handler {
	type client struct {
		limiter  *rate.Limiter
		lastSeen time.Time
	}
	var mu sync.Mutex
	var clients = make(map[string]*client)

	go func() {
		for {
			time.Sleep(time.Minute)

			mu.Lock()

			for ip, client := range clients {
				if time.Since(client.lastSeen) > 3*time.Minute {
					delete(clients, ip)
				}
			}
			mu.Unlock()
		}
	}()

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a.config.limiter.enabled {
			ip, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				a.serverErrResponse(w, r, err)
				return
			}

			mu.Lock()

			_, found := clients[ip]

			if !found {
				clients[ip] = &client{limiter: rate.NewLimiter(rate.Limit(a.config.limiter.rps), a.config.limiter.burst)}
			}

			clients[ip].lastSeen = time.Now()

			if !clients[ip].limiter.Allow() {
				mu.Unlock()
				a.rateLimitExceededResponse(w, r)
				return
			}

			mu.Unlock()

		}

		next.ServeHTTP(w, r)
	})
}

func (a *appDependencies) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		/*This header tells the servers not to cache the response when
		the Authorization header changes. This also means that the server is not
		supposed to serve the same cached data to all users regardless of their
		Authorization values. Each unique user gets their own cache entry*/
		w.Header().Add("Vary", "Authorization")

		/*Get the Authorization Header from the request. It should have the Bearer token*/
		authorizationHeader := r.Header.Get("Authorization")

		//if no authorization header found, then its an anonymous user
		if authorizationHeader == "" {
			r = a.contextSetUser(r, data.AnonymouseUser)
			next.ServeHTTP(w, r)
			return
		}
		/* Bearer token present so parse it. The Bearer token is in the form
		Authorization: Bearer IEYZQUBEMPPAKPOAWTPV6YJ6RM
		We will implement invalidAuthenticationTokenResponse() later */

		headerParts := strings.Split(authorizationHeader, " ")
		if len(headerParts) != 2 || headerParts[0] != "Bearer" {
			a.invalidAuthenticationTokenResponse(w, r)
			return
		}
		//get the actual token
		token := headerParts[1]
		//validatte
		v := validator.New()

		data.ValidatetokenPlaintext(v, token)
		if !v.IsEmpty() {
			a.invalidAuthenticationTokenResponse(w, r)
			return
		}

		//get the user info relatedw with this authentication token
		user, err := a.userModel.GetForToken(data.ScopeAuthentication, token)
		if err != nil {
			switch {
			case errors.Is(err, data.ErrRecordNotFound):
				a.invalidAuthenticationTokenResponse(w, r)
			default:
				a.serverErrResponse(w, r, err)
			}
			return
		}
		//add the retrieved user info to the context
		r = a.contextSetUser(r, user)
		//call the next handler in the chair
		next.ServeHTTP(w, r)
	})
}

// check if the user is authenticated NOTE: not anonymous
func (a *appDependencies) requireAuthenticatedUser(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := a.contextGetUser(r)

		if user.IsAnonymous() {
			a.authenticationRequiredResponse(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// check if user is activated
func (a *appDependencies) requireActivatedUser(next http.HandlerFunc) http.HandlerFunc {
	fn := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := a.contextGetUser(r)

		if !user.Activated {
			a.inactiveAccountResponse(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})

	//We pass the activation check middleware to the authentication
	// middleware to call (next) if the authentication check succeeds
	// In other words, only check if the user is activated if they are
	// actually authenticated.
	return a.requireAuthenticatedUser(fn)
}

func (a *appDependencies) requirePermission(permissionCode string, next http.HandlerFunc) http.HandlerFunc {

	fn := func(w http.ResponseWriter, r *http.Request) {
		user := a.contextGetUser(r)
		// get all the permissions associated with the user
		permissions, err := a.permissionModel.GetAllForUser(user.ID)
		if err != nil {
			a.serverErrResponse(w, r, err)
			return
		}
		if !permissions.Include(permissionCode) {
			a.notPermittedResponse(w, r)
			return
		}
		// they are good. Let's keep going
		next.ServeHTTP(w, r)
	}

	return a.requireActivatedUser(fn)

}

// SCENARIO #1: Let's assume our API is a public API. Anyone can use it once they
// signup. So for the clients' browsers to be able to read our API responses, we
// need to set the Access-Control-Allow-Origin header to everyone
// (using the * operator). Notice we are back to returning 'http.Handler'
// Also notice that this middleware sets the header on the response object (w). We
// set the response header early in the middleware chain to enable our
// response to be accepted by the client's browser

// func (a *appDependencies) enableCORS(next http.Handler) http.Handler {
// 	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
// 		w.Header().Set("Access-Control-Allow-Origin", "*")

// 		next.ServeHTTP(w, r)
// 	})
// }

func (a *appDependencies) enableCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Vary", "Origin")
		// The request method can vary so don't rely on cache
		w.Header().Add("Vary", "Access-Control-Request-Method")
		origin := r.Header.Get("Origin")

		if origin != "" {
			for i := range a.config.cors.trustedOrigins {
				if origin == a.config.cors.trustedOrigins[i] {
					w.Header().Set("Access-Control-Allow-Origin", origin)
					// check if it is a Preflight CORS request
					if r.Method == http.MethodOptions &&
						r.Header.Get("Access-Control-Request-Method") != "" {
						w.Header().Set("Access-Control-Allow-Methods",
							"OPTIONS, PUT, PATCH, DELETE")
						w.Header().Set("Access-Control-Allow-Headers",
							"Authorization, Content-Type")

						// we need to send a 200 OK status. Also since there
						// is no need to continue the middleware chain we
						// we leave  - remember it is not a real 'comments' request but
						// only a preflight CORS request
						w.WriteHeader(http.StatusOK)
						return
					}
					break
				}
			}
		}

		next.ServeHTTP(w, r)

	})
}
