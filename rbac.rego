package rbac

import rego.v1

# context objects
user_attributes := {
	"alice": {"noOfAccounts": 1, "title": "customer"},
	"bob": {"noOfAccounts": 0, "title": "employee"},
	"Rebecca": {"noOfAccounts": 0, "title": "advisor"}
}

# employee permissions attributes
employee_attributes := {
	"accounts": "read",
	"cards": "read"
}

# customer permissions attributes
customer_attributes := {
	"accounts": "write",
	"cards": "write"
}

# advisor permissions attributes
advisor_attributes := {
	"accounts": "admin",
	"cards": "admin"
}

default allow := false

# allow read/write access when customer have atleast one account opened
allow if {
	# lookup the user's attributes
	user := user_attributes[input.user]
	# check that the user is a customer
	user.title == "customer"
    	# check customer has atleast one account 
    	user.noOfAccounts >= 1
    	# allow only read/write access to accounts or cards 
    	employee_attributes[input.resource] == input.access
}
