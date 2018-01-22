<?php

if ( ! defined( 'JWT_AUTH_VERSION' ) ) {
	define( 'JWT_AUTH_VERSION', '0.0.1' );
}

\AaronHolbrook\Autoload\autoload( dirname( __FILE__ ) . '/includes' );

JWT\API\setup();
JWT\Auth\setup();
JWT\Headers\setup();
