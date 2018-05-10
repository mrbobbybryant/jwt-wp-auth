<?php
namespace JWT\JWT;

use JWT\Headers;

if ( ! defined( 'ABSPATH' ) ) {
	exit; // Exit if accessed directly.
}

/**
 * Function create a valide json web token for the input user account.
 *
 * @param [object] $user WP User Object.
 * @return object
 */
function create( $user ) {
	$expiration  = defined( 'JWT_EXPIRATION' ) && JWT_EXPIRATION ? JWT_EXPIRATION : ( 24 * 60 * 60 );
	$token_id    = base64_encode( random_bytes( 32 ) );
	$issued_at   = time();
	$not_before  = $issued_at + 10;
	$expire      = $not_before + $expiration;
	$server_name = gethostname();

	/*
	 * Create the token as an array
	 */
	$data = [
		'iat'  => $issued_at,
		'jti'  => $token_id,
		'iss'  => $server_name,
		'nbf'  => $not_before,
		'exp'  => $expire,
		'data' => [
			'userId' => is_object( $user ) ? $user->ID : $user,
		],
	];

	/*
	 * Extract the key, which is coming from the config file.
	 *
	 * Best suggestion is the key to be a binary string and
	 * store it in encoded in a config file.
	 *
	 * Can be generated with base64_encode(openssl_random_pseudo_bytes(64));
	 *
	 * keep it secure! You'll need the exact key to verify the
	 * token later.
	 */
	$secret_key = defined( 'JWT_SECRET_TOKEN' ) && JWT_SECRET_TOKEN ? JWT_SECRET_TOKEN : (string) wp_rand();

	/*
	 * Encode the array to a JWT string.
	 * Second parameter is the key to encode the token.
	 *
	 * The output string can be validated at http://jwt.io/
	 */
	$jwt = \Firebase\JWT\JWT::encode(
		$data,
		$secret_key,
		'HS256'
	);

	return [ 'jwt' => $jwt ];
}

/**
 * Function is used during authenticated requests to validate a json web token.
 *
 * @param [string] $header Authorization Header string.
 * @return WP_Error|boolean
 */
function validate( $header ) {
	$jwt = Headers\get_bearer_token( $header );

	if ( $jwt ) {

		try {
			/*
			 * decode the jwt using the key from config
			 */
			$token = \Firebase\JWT\JWT::decode( $jwt, JWT_SECRET_TOKEN, array( 'HS256' ) );

			return $token;

		} catch ( \Exception $e ) {
			/*
			 * the token was not able to be decoded.
			 * this is likely because the signature was not able to be verified (tampered token)
			 */
			$error = new \WP_Error(
				'jwt_error',
				sprintf( 'Unable to validate token. %s', $e->getMessage() ),
				array( 'status' => 401 )
			);
			return rest_ensure_response( $error );
		}
	} else {
		/*
		 * The request lacks the authorization token
		 */
		return new \WP_Error(
			'jwt_error',
			esc_html__( 'Bad Request', 'archsystems' ),
			array( 'status' => 400 )
		);
	}

	return true;

}
