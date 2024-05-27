package app.rbac


default allow = false

allow {
	user_is_admin
}


allow {
	# load context object for request 
	response := http.send({
        "method": "POST",
        "url": "https://localhost:9200/customer/_search",
        "headers": {
            "content-type": "application/json"
        },
		"body": {
  					"query": {
    				"match": {
      					"email": input.body.email
    					}
  					}
				}
    	})

	print("response:", response.hits.total.value)


	# Find permissions for the user.
	some permission
	user_is_granted[permission]

	# Check if the permission permits the action.
	input.action == permission.action
	input.type == permission.type

	# unless user location is outside US
	country := data.users[input.user].location.country
	country == "US"
}

user_is_admin {
	# for some `i`...
	some i

	# "admin" is the `i`-th element in the user->role mappings for the identified user.
	data.users[input.user].roles[i] == "admin"
}

user_is_viewer {
	# for some `i`...
	some i

	# "viewer" is the `i`-th element in the user->role mappings for the identified user.
	data.users[input.user].roles[i] == "viewer"
}

user_is_guest {
	# for some `i`...
	some i

	# "guest" is the `i`-th element in the user->role mappings for the identified user.
	data.users[input.user].roles[i] == "guest"
}


user_is_granted[permission] {
	some i, j

	# `role` assigned an element of the user_roles for this user...
	role := data.users[input.user].roles[i]

	# `permission` assigned a single permission from the permissions list for 'role'...
	permission := data.role_permissions[role][j]
}
