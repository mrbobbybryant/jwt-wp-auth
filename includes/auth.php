<?php
namespace JWT\Auth;

use JWT\Headers;
use JWT\JWT;

function setup() {
	add_filter( 'determine_current_user', __NAMESPACE__ . '\json_basic_auth_handler', 20 );
	add_filter( 'rest_authentication_errors', __NAMESPACE__ . '\json_basic_auth_error' );
}

/**
 * Plugin Name: JSON Basic Authentication
 * Description: Basic Authentication handler for the JSON API, used for development and debugging purposes
 * Author: WordPress API Team
 * Author URI: https://github.com/WP-API
 * Version: 0.1
 * Plugin URI: https://github.com/WP-API/Basic-Auth
 */
function json_basic_auth_handler( $user ) {
	global $wp_json_basic_auth_error;
	$wp_json_basic_auth_error = null;
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
		$wp_json_basic_auth_error = $token;
		return null;
	}

	$wp_json_basic_auth_error = true;
	return $token->data->userId;
}

function json_basic_auth_error( $error ) {
	// Passthrough other errors.
	if ( ! empty( $error ) ) {
		return $error;
	}

	global $wp_json_basic_auth_error;
	return $wp_json_basic_auth_error;
}
