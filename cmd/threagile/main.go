package main

import (
	"github.com/Pinguladora/threagile/internal/threagile"
)

var buildTimestamp = ""

func main() {
	new(threagile.Threagile).Init(buildTimestamp).Execute()
}
