package http

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"os/exec"
	"runtime"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const (
	clientID     = "YOUR_CLIENT_ID"
	clientSecret = "YOUR_CLIENT_SECRET"
	redirectURL  = "http://localhost:8080/callback"
	issuerURL    = "https://YOUR_ISSUER_DOMAIN" // e.g., https://accounts.google.com
)

var (
	state = randomString(16)
)

func main() {
	ctx := context.Background()

	provider, err := oidc.NewProvider(ctx, issuerURL)
	if err != nil {
		log.Fatalf("Failed to get provider: %v", err)
	}

	oauth2Config := oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}

	// Prepare verifier
	verifier := provider.Verifier(&oidc.Config{ClientID: clientID})

	// Start HTTP server
	http.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("state") != state {
			http.Error(w, "State mismatch", http.StatusBadRequest)
			return
		}

		code := r.URL.Query().Get("code")
		token, err := oauth2Config.Exchange(ctx, code)
		if err != nil {
			http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
			return
		}

		rawIDToken, ok := token.Extra("id_token").(string)
		if !ok {
			http.Error(w, "No id_token in token response", http.StatusInternalServerError)
			return
		}

		idToken, err := verifier.Verify(ctx, rawIDToken)
		if err != nil {
			http.Error(w, "Failed to verify ID Token: "+err.Error(), http.StatusInternalServerError)
			return
		}

		var claims map[string]interface{}
		if err := idToken.Claims(&claims); err != nil {
			http.Error(w, "Failed to parse claims: "+err.Error(), http.StatusInternalServerError)
			return
		}

		fmt.Fprintf(w, "Login successful!\n\nClaims:\n%v", claims)
		log.Printf("Access Token: %s\nID Token Claims: %+v\n", token.AccessToken, claims)

		go func() {
			time.Sleep(2 * time.Second)
			log.Println("Shutting down server...")
			srv := &http.Server{Addr: ":8080"}

			go func() {
				log.Println("Starting local server at http://localhost:8080/callback")
				if err := srv.ListenAndServe(); err != http.ErrServerClosed {
					log.Fatalf("Server failed: %v", err)
				}
			}()

			// Inside your /callback handler, replace the shutdown logic:
			go func() {
				time.Sleep(2 * time.Second)
				log.Println("Shutting down server...")
				if err := srv.Shutdown(context.Background()); err != nil {
					log.Printf("Error shutting down server: %v", err)
				}
			}()
		}()
	})

	go func() {
		log.Println("Starting local server at http://localhost:8080/callback")
		_ = http.ListenAndServe(":8080", nil)
	}()

	// Open browser
	url := oauth2Config.AuthCodeURL(state)
	fmt.Println("Opening browser to:", url)
	openBrowser(url)

	// Block until interrupt
	select {}
}

func randomString(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)[:n]
}

func openBrowser(url string) {
	var err error
	switch runtime.GOOS {
	case "linux":
		err = exec.Command("xdg-open", url).Start()
	case "windows":
		err = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		err = exec.Command("open", url).Start()
	default:
		err = fmt.Errorf("unsupported platform")
	}
	if err != nil {
		log.Printf("Please open this URL manually: %s\n", url)
	}
}
