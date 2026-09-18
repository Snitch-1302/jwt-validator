package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
)

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

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if strings.HasSuffix(entry.Name(), ".jwt") {
			fmt.Println("Found token file:", entry.Name())

			path := "tokens/" + entry.Name()

			data, err := os.ReadFile(path)
			if err != nil {
				fmt.Println("Error reading file:", err)
				continue
			}

			tokenString := strings.TrimSpace(string(data))

			token, err := jwt.Parse(tokenString, keyFunc)
			if err != nil {
				fmt.Println("Invalid:", err)
			} else {
				claims, _ := token.Claims.(jwt.MapClaims)
				missing := ""
				for _, rc := range requiredClaims {
					if _, exists := claims[rc]; !exists {
						missing = rc
					}
				}
				if missing != "" {
					fmt.Println("Invalid: missing required claim:", missing)
				} else {
					fmt.Println("Valid")
					fmt.Println("Claims:", claims)
				}
			}
		}
	}
}