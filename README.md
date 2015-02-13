# Goauth for Go

The `goauth` package contains a simplified implementation of OAuth 1.0
and OAuth 2.0 spec for the Go programming language.

# Installation

    go get "github.com/rchargel/goauth"

# Import

    import "github.com/rchargel/goauth"

# Documentation

The package documentation can be found at
[http://godoc.org/github.com/rchargel/goauth](http://godoc.org/github.com/rchargel/goauth).

# Dependencies

* `golang.org/x/oauth2` - the OAuth 2.0 service provider wraps this API.

# Implementation Description

Package goauth is a simple to use and implement tool to configure OAuth
authentication for your application or service. It relies on some of the
OAuth tools already available for Go, but adds in some structure to
reduce the complexity of your implementation. The intent is to make
authentication easy by reducing the pain points to just a couple of
configuration parameters.

This package provides two OAuth implementations, Version 1.0 and Version
2.0. For version 2.0 implementations the sequence of events is fairly
straightforward.

	Browser                    Server                   Provider
	   |                          |                          |
	   # GET: /oauth/provider     |                          |
	   #==>==>==>==>==>==>==>==>=>#                          |
	   |            Send Redirect #                          |
	   #<=<==<==<==<==<==<==<==<==#                          |
	   # Redirect to provider login                          |
	   #==>==>==>==>==>==>==>==>==|==>==>==>==>==>==>==>==>=>#
	   |                          |                          # User logs in
	   |                          | Redirect to callback URL #
	   #<=<==<==<==<==<==<==<==<==|==<==<==<==<==<==<==<==<==#
	   # GET: Callback URL        |                          |
	   #==>==>==>==>==>==>==>==>=>#                          |
	   |                          # GET: User Info           |
	   |                          #==>==>==>==>==>==>==>==>=>#
	   |                          #<=<==<==<==<==<==<==<==<==#
	   |                          # Process User             |
	   |                          # Create Session           |
	   |          Respond To User #                          |
	   #<=<==<==<==<==<==<==<==<==#                          |
	   #                          |                          |

For version 1.0 implementations the sequence of events is slightly more
complex, however most of that complexity is hidden from you by the API.

	Browser                    Server                    Provider
	   |                          |                          |
	   # GET: /oauth/provider     |                          |
	   #==>==>==>==>==>==>==>==>=>#                          |
	   |                          # Fetch OAuth Token        |
	   |                          #==>==>==>==>==>==>==>==>=>#
	   |                          #                          # Auth Request
	   |                          #  Return Token and Secret #
	   |                          #<=<==<==<==<==<==<==<==<==#
	   |            Send Redirect #                          |
	   #<=<==<==<==<==<==<==<==<==#                          |
	   # Redirect to provider login                          |
	   #==>==>==>==>==>==>==>==>==|==>==>==>==>==>==>==>==>=>#
	   |                          |                          # User logs in
	   |                          | Redirect to callback URL #
	   #<=<==<==<==<==<==<==<==<==|==<==<==<==<==<==<==<==<==#
	   # GET: Callback URL        |                          |
	   #==>==>==>==>==>==>==>==>=>#                          |
	   |                          # Fetch Access Token       |
	   |                          #==>==>==>==>==>==>==>==>=>#
	   |                          #                          # Auth Request
	   |                          #      Return Access Token #
	   |                          #<=<==<==<==<==<==<==<==<==#
	   |                          # GET: User Info           |
	   |                          #==>==>==>==>==>==>==>==>=>#
	   |                          #<=<==<==<==<==<==<==<==<==#
	   |                          # Process User             |
	   |                          # Create Session           |
	   |          Respond To User #                          |
	   #<=<==<==<==<==<==<==<==<==#                          |
	   #                          |                          |

# Testing

So far, I have only tested this API with the following OAuth Providers:

* **OAuth 2.0**
  * Google
  * Facebook
* **OAuth 1.0**
  * Twitter

# Contact Me

Contact me with any questions or comments through my website: [http://zcarioca.net](http://zcarioca.net).
