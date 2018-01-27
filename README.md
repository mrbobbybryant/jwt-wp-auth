# JSON Web Token WP Auth

This package provides all the mechanisms needed to authenticate and make authenticated request with the WordPress Rest API using JSON Web Tokens.


# Key Features

- Provides a Login Endpoint, which expects a valid WordPress Username and Password.
- Provides a register endpoint, which uses the **Anyone can register** option in **Settings->General** to turn this feature on and off.
- Expects a Authorization: Bearer Token on all Authenticated Requests.

## Installation

### (Option 1) Use composer.

Step 1: Add jwt-wp-auth to composer.json repositories section.

         "repositories" : [
                  {
                           "type": "vcs",
                           "url": "https://github.com/mrbobbybryant/jwt-wp-auth"
                  }
         ]

Step 2: Add jwt-wp-auth to composer.json require section.
 
         "developwithwp/wp-rest-meta": "dev-master"
         
Step 3: Add Composer Autoload Call to your `functions.php` if you have not already.
 
         if ( file_exists( get_template_directory() . '/vendor/autoload.php' ) ) {
            require( 'vendor/autoload.php' );
         }

Step 4: Run `composer update or composer install`

### (Option 2) Clone Github repo

Step 1: Clone repo into you theme folder.
 
         git clone https://github.com/mrbobbybryant/jwt-wp-auth.git

Step 2: Require the root file for jwt-wp-auth in you `functions.php` file.

         if ( file_exists( get_template_directory() . '/jwt-wp-auth/index.php' ) ) {
            require_once get_template_directory() . '/jwt-wp-auth/index.php';
         }

## Usage

While not required, there are a number of PHP constants you should set in your `wp-config.php` to tell jwt-wp-auth how you would like it do work.

### JWT_SECRET_TOKEN
```define( 'JWT_SECRET_TOKEN', 'TIRUDHx46RUx6D' ); <---- Just an example secret```

This secret token is used to encrypt all the JSON web tokens issued by jwt-wp-auth. This is what makes JWT's work in general. Only the issuer, i.e. your server has this key, so only it can create valid tokens for your website. It is important that this never be publicly exposed. For that reason it is recommended that you add this to your project's `wp-config.php`.

### JWT_ORIGIN

In order for you to make Cross-site requests we need to enable CORS support for the REST API. By default jwt-wp-auth turns this on for you, and it sets the `Access-Control-Allow-Origin` to `*`. This means any website can send a CORS requst to your server. However, from a security perspective this is less than ideal. You should actually set this to a limited number of website urls.

That's where this constant comes into play. It lets you define a specific site url.

```define( 'JWT_ORIGIN', 'http://localhost:3000' );```

In the  above example I am setting my CORS to only allow request from `http://localhost:3000`. This is a much safer approach, so I encourage you to set this constant.

### JWT_EXPIRATION

For security reasons, when a JWT is created we only want it to be good for a limited time. Luckily when a JWT is created by jwt-wp-auth an expiration is set. By default that expiration is in **24 Hours**.

But if you define this constant in your `wp-config.php`, you can override this default and set your JWT token to a different expiration.

```define( 'JWT_EXPIRATION', 36000 );```

In the above example, I am overriding the default 24hours expiration, and I am instead setting my token to expire in **10 Hours**. `36000 = 10 Hours in seconds`

## Getting a Token

To get a token you must make an HTTP request to the `/wp-json/jwt/v1/auth/login` endpoint. Below is an example request using the Javascript Fetch API. This endpoint expects a `username` and `password`.

```
const url = 'https://my-site.com';
const loginEndpoint = '/wp-json/jwt/v1/auth/login';
fetch(`${url}${loginEndpoint}?username=${username}&password=${password}`)
```

In this example we are sending the username and password as query args.

This endpoint will return a JWT token if the username and password are valid. Otherwise it will return various errors. Here is a more complete request that handles those different responses.

```
const url = 'https://my-site.com';
const loginEndpoint = '/wp-json/jwt/v1/auth/login';
fetch(`${url}${loginEndpoint}?username=${username}&password=${password}`)
	.then(response => response.json())
    .then(json => {
	  //Catch an errors.
      if (json.code) {
        this.onError(json);
      }
		
	  //Success! Lets save taht token and redirect the user, or something....
      if (json.jwt) {
        localStorage.setItem('token', json.jwt);
        this.props.history.push('/');
      }
    })
    .catch(err => {
      console.warn(err);
    });

onError = err => {
  if ('invalid_username' === err.code) {
    this.setState({ usernameError: 'Invalid Username or password.' });
  }

  if ('incorrect_password' === err.code) {
    this.setState({ passwordError: 'Invalid Username or password.' });
  }
};
```

## Create a User

The other endpoint provided by jwt-wp-auth is `/wp-json/jwt/v1/auth/register`. This endpoint is needed since the Core Rest API endpoints for users do not allow anonymous user creation.

> **Note:** This endpoint will only work if you check the **Anyone can register** option on the **Settings -> General** page inside the WordPress Admin.

Below is an example request using the Javascript Fetch API. This endpoint expects a `username`, `password`, and `email`.

```
const url = 'https://my-site.com';
const loginEndpoint = '/wp-json/jwt/v1/auth/register';
fetch(`${url}${loginEndpoint}?username=${username}&password=${password}&${email}`, {
	method: 'POST',
})
```

And similar to the login example, this endpoint will return a JWT on success, or it will return various errors. For example if that username or email already exists then you will get an error.

## Making an Authenticated Request.

Once you have completed the login and have been issued a JWT, you are ready to start interacting with the Rest API. Let's say we wanted to get a list of Private Posts. Private content is published only for your eyes, or the eyes of only those with authorization permission levels to see private content. So an "admin" user can see this but a "subscriber" user will not.

So if we are logged in as an admin user, we can send our JWT in our request and see the private posts.

```
const endpoint = 'https://my-site.com/wp-json/wp/v2/posts?status=private';
const requestObject = {
  method: 'GET',
  headers: {
    'Authorization': 'Bearer ' + my.JWT, //This is your token.
  }
}

fetch( endpoint, requestObject );
```

An admin user's JWT will allow them to see the private posts, but a subscribers JWT will give them an unauthorized error.

## Roadmap
- Create React App example which uses this library for login, registration, protect routes, etc.