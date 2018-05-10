<?php
namespace JWT\Auth;

use JWT\Headers;
use JWT\JWT;

if ( ! defined( 'ABSPATH' ) ) {
	exit; // Exit if accessed directly.
}

/**
 * Function handles bootstrapping the JWT Auth Process.
 *
 * @return void
 */
function setup() {
	add_filter( 'determine_current_user', __NAMESPACE__ . '\json_jwt_auth_handler', 20 );
	add_filter( 'rest_authentication_errors', __NAMESPACE__ . '\json_jwt_auth_error' );
}

/**
 * Function hooks into the get current users process used by the Rest API and validates the
 * current users by extracting the user_id from a json web token. This code was primarily lifted from the
 * basic auth plugin. So Props to them for the over process.
 *
 * @param [object] $user WP User Object
 * @return void|int
 */
function json_jwt_auth_handler( $user ) {
	global $wp_json_jwt_auth_error;
	$wp_json_jwt_auth_error = null;
	// Don't authenticate twice.
	if ( ! empty( $user ) ) {
		return $user;
	}

	$headers = Headers\get_authorization();

	if ( ! $headers ) {
		return $user;
	}

	/**
	 * In multi-site, wp_authenticate_spam_check filter is run on authentication. This filter calls
	 * get_currentuserinfo which in turn calls the determine_current_user filter. This leads to infinite
	 * recursion and a stack overflow unless the current function is removed from the determine_current_user
	 * filter during authentication.
	 */
	remove_filter( 'determine_current_user', 'json_basic_auth_handler', 20 );

	$token = JWT\validate( $headers );

	add_filter( 'determine_current_user', 'json_basic_auth_handler', 20 );

	if ( is_wp_error( $token ) ) {
		$wp_json_jwt_auth_error = $token;
		return null;
	}

	$wp_json_jwt_auth_error = true;
	return $token->data->userId;
}

/**
 * Function ensures authentication errors are returned to the client in the event that the
 * jwt auth process fails.
 *
 * @param [object] $error WP_Error.
 * @return object
 */
function json_jwt_auth_error( $error ) {
	// Passthrough other errors.
	if ( ! empty( $error ) ) {
		return rest_ensure_response( $error );
	}

	global $wp_json_jwt_auth_error;
	return rest_ensure_response( $wp_json_jwt_auth_error );
}
