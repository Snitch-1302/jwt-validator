package main

import (
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
)

type ValidationResult struct {
	Filename string
	Message  string
}

func main() {

	godotenv.Load()
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		fmt.Println("Error: JWT_SECRET environment variable not set")
		return
	}

	entries, err := os.ReadDir("tokens")
	if err != nil {
		fmt.Println("Error reading directory:", err)
		return
	}

	allowedAlgs := []string{"HS256"}
	requiredClaims := []string{"sub", "exp"}
	allowedKids := []string{"key1", ""} // "" allows tokens with no kid at all

	keyFunc := func(token *jwt.Token) (interface{}, error) {
		alg := token.Method.Alg()
		algOK := false
		for _, a := range allowedAlgs {
			if alg == a {
				algOK = true
			}
		}
		if !algOK {
			return nil, fmt.Errorf("algorithm not allowed: %v", alg)
		}

		kid, _ := token.Header["kid"].(string)
		kidOK := false
		for _, k := range allowedKids {
			if kid == k {
				kidOK = true
			}
		}
		if !kidOK {
			return nil, fmt.Errorf("kid not allowed: %v", kid)
		}

		return []byte(secret), nil
	}

	var wg sync.WaitGroup
	results := make(chan ValidationResult, len(entries))

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if strings.HasSuffix(entry.Name(), ".jwt") {

			wg.Add(1)

			go func(entry os.DirEntry) {
				defer wg.Done()

				filename := entry.Name()
				path := "tokens/" + filename

				data, err := os.ReadFile(path)
				if err != nil {
					results <- ValidationResult{
						Filename: filename,
						Message:  "Error reading file: " + err.Error(),
					}
					return
				}

				tokenString := strings.TrimSpace(string(data))

				token, err := jwt.Parse(tokenString, keyFunc)
				if err != nil {
					results <- ValidationResult{
						Filename: filename,
						Message:  "Invalid: " + err.Error(),
					}
					return
				}

				claims, _ := token.Claims.(jwt.MapClaims)

				missing := ""
				for _, rc := range requiredClaims {
					if _, exists := claims[rc]; !exists {
						missing = rc
					}
				}

				if missing != "" {
					results <- ValidationResult{
						Filename: filename,
						Message:  "Invalid: missing required claim: " + missing,
					}
					return
				}

				results <- ValidationResult{
					Filename: filename,
					Message:  "Valid",
				}
			}(entry)
		}
	}

	wg.Wait()
	close(results)

	for r := range results {
		fmt.Println(r.Filename, r.Message)
	}
}