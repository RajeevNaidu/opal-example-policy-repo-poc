package api.v1

default products = false


# Allow bob to do anything
products {
	input.user == "bob"
}
