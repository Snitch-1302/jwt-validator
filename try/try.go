package main

import (
	"fmt"
	"sync"
)

type ValidationResult struct {
	Filename string
	Message  string
}

func myFunc(n int, wg *sync.WaitGroup) {
	defer wg.Done()

	fmt.Println("hello from goroutine", n)
}

func main() {
	var wg sync.WaitGroup

	for i := 0; i < 5; i++ {
		wg.Add(1)
		go myFunc(i, &wg)
	}

	wg.Wait()
}