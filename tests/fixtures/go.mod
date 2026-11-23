module example.com/app

go 1.23

require (
	github.com/spf13/cobra v1.8.0
	golang.org/x/net v0.25.0 // indirect
)

require github.com/inconshreveable/mousetrap v1.1.0 // indirect

replace golang.org/x/net => github.com/example/net-fork v0.25.1

replace example.com/local => ../local
