# GO JWT Middleware

A middleware that will check that a [JWT](http://jwt.io/) is sent on the `Authorization` header and will then set the content of the JWT into the `user` variable of the request.

This module lets you authenticate HTTP requests using JWT tokens in your Go Programming Language applications. JWTs are typically used to protect API endpoints, and are often issued using OpenID Connect.

## Key Features

* Ability to **check the `Authorization` header for a JWT**
* **Decode the JWT** and set the content of it to the request context

## Installing

````bash
go get github.com/auth0/go-jwt-middleware
````

## Changes in this fork

I'm changing this from working with `gorilla/context` to goji's `web.C`.

## Original Author

[Auth0](auth0.com)

## License

This project is licensed under the MIT license. See the [LICENSE](LICENSE.txt) file for more info.
