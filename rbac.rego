# Role-based Access Control (RBAC)
# --------------------------------
#
# This example defines an RBAC model for a Pet Store API. The Pet Store API allows
# users to look at pets, adopt them, update their stats, and so on. The policy
# controls which users can perform actions on which resources. The policy implements
# a classic Role-based Access Control model where users are assigned to roles and
# roles are granted the ability to perform some action(s) on some type of resource.
#
# This example shows how to:
#
#	* Define an RBAC model in Rego that interprets role mappings represented in JSON.
#	* Iterate/search across JSON data structures (e.g., role mappings)
#
# For more information see:
#
#	* Rego comparison to other systems: https://www.openpolicyagent.org/docs/latest/comparison-to-other-systems/
#	* Rego Iteration: https://www.openpolicyagent.org/docs/latest/#iteration

package app.rbac

import rego.v1

default allow := false

allow if {
	# The `some` keyword declares local variables. This example declares a local
	# variable called `user_name` (used below).
	some user_name

	input.attributes.request.http.method == "GET"

	# The `=` operator in Rego performs pattern matching/unification. OPA finds
	# variable assignments that satisfy this expression (as well as all of the other
	# expressions in the same rule.)
	input.parsed_path = ["headers", "users", user_name]

	# Check if the `user_name` from path is the same as the username from the
	# credentials.
	user_name == "bob"
}

