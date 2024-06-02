package api.v1

default allow = false


# Allow bob to do anything
products {
	input.user == "bob"
}
