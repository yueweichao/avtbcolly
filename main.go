package main

import (
	"fmt"
	"net/url"
)

const u = "http://www.baidu.com"

func main() {
	pu, err := url.Parse(u)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(pu)
}
