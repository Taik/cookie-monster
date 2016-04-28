package main

import (
	"fmt"

	"github.com/Taik/cookie-monster/cookies"
)

func main() {
	cookies, err := cookie.Chrome("https://www.instagram.com/", "")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Printf("%v\n", cookies)
}
