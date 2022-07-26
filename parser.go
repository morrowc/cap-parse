package main

import "flag"

var (
	input = flag.String("input", "", "Capture file to parse")
)

func main() {
	flag.Parse()

}
