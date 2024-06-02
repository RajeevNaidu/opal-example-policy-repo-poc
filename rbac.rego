package rbac

default allow = false


# Allow bob to do anything
allow {
	input.user == "bob"
}
