<?php
namespace JWT\JWT;

use JWT\Headers;

function create( $user ) {
	$token_id    = base64_encode( random_bytes( 32 ) );
	$issued_at   = time();
	$not_before  = $issued_at + 10;             // Adding 10 seconds.
	$expire      = $not_before + 6000;            // Adding 60 seconds.
	$server_name = 'archsystems'; // Retrieve the server name from config file.

	/*
	 * Create the token as an array
	 */
	$data = [
		'iat'  => $issued_at,         // Issued at: time when the token was generated.
		'jti'  => $token_id,          // Json Token Id: an unique identifier for the token.
		'iss'  => $server_name,       // Issuer.
		'nbf'  => $not_before,        // Not before.
		'exp'  => $expire,           // Expire.
		'data' => [                  // Data related to the signer user.
			'userId' => $user->ID, // User ID.
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
		$data,      // Data to be encoded in the JWT.
		$secret_key, // The signing key.
		'HS256'     // Algorithm used to sign the token, see https://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-40#section-3.
	);

	return [ 'jwt' => $jwt ];
}

function validate( $header ) {
		$jwt = Headers\get_bearer_token( $header );

		/*
		 * Look for the 'authorization' header
		 */
	if ( $jwt ) {

		try {
			/*
			 * decode the jwt using the key from config
			 */

			$token = \Firebase\JWT\JWT::decode( $jwt, JWT_SECRET_TOKEN, array( 'HS256' ) );

			return $token;

		} catch ( Exception $e ) {
			/*
			 * the token was not able to be decoded.
			 * this is likely because the signature was not able to be verified (tampered token)
			 */
			return new \WP_Error(
				'jwt_error',
				esc_html__( 'You are not allowed to do this..', 'archsystems' ),
				array( 'status' => 401 )
			);
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

}
