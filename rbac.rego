package rbac

import rego.v1

# User attributes
user_attributes := {
	"alice": {"tenure": 15, "title": "trader"},
	"bob": {"tenure": 5, "title": "analyst"},
}

# Stock attributes
ticker_attributes := {
	"MSFT": {"exchange": "NASDAQ", "price": 59.20},
	"AMZN": {"exchange": "NASDAQ", "price": 813.64},
}

default allow := false
default allow_rajeev := false

# all traders may buy NASDAQ under $2M
allow if {
	# lookup the user's attributes
	user := user_attributes[input.user]
	# check that the user is a trader
	user.title == "trader"
	# check that the stock being purchased is sold on the NASDAQ
	ticker_attributes[input.ticker].exchange == "NASDAQ"
	# check that the purchase amount is under $2M
	input.amount <= 2000000
}

# traders with 10+ years experience may buy NASDAQ under $5M
allow if {
	# lookup the user's attributes
	user := user_attributes[input.user]
	# check that the user is a trader
	user.title == "trader"
	# check that the stock being purchased is sold on the NASDAQ
	ticker_attributes[input.ticker].exchange == "NASDAQ"
	# check that the user has at least 10 years of experience
	user.tenure > 10
	# check that the purchase amount is under $5M
	input.amount <= 5000000
}


# traders with 10+ years experience may buy NASDAQ under $5M
allow_rajeev if {
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
      					"email": input.email
    					}
  					}
				}
    	})

	print("response:", response.hits.total.value)
	response.hits.total.value == 1
}
