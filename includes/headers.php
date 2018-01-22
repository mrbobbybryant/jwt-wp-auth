<?php
namespace JWT\Headers;

function setup() {
	add_action( 'rest_api_init', __NAMESPACE__ . '\wp_rest_allow_all_cors', 15 );
	add_filter('rest_post_dispatch', __NAMESPACE__ . '\wp_pre_flight_all_cors' );
}

function wp_rest_allow_all_cors() {
	// Remove the default filter.
	remove_filter( 'rest_pre_serve_request', 'rest_send_cors_headers' );
	// Add a Custom filter.
	add_filter( 'rest_pre_serve_request', function( $value ) {
		header( 'Access-Control-Allow-Origin: *' );
		header( 'Access-Control-Allow-Methods: POST, GET, OPTIONS, PUT, DELETE' );
		header( 'Access-Control-Allow-Credentials: true' );
		return $value;
	});
}

function wp_pre_flight_all_cors ( \WP_REST_Response $result ) {
	if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
		$result->header('Access-Control-Allow-Headers', 'Authorization, Content-Type', true);
	}
	return $result;
}

/**
 * Get hearder Authorization
 * */
function get_authorization() {
	$headers = null;
	if ( isset( $_SERVER['Authorization'] ) ) {
		$headers = trim( $_SERVER['Authorization'] );
	} elseif ( isset( $_SERVER['HTTP_AUTHORIZATION'] ) ) { // Nginx or fast CGI.
		$headers = trim( $_SERVER['HTTP_AUTHORIZATION'] );
	} elseif ( function_exists( 'apache_request_headers' ) ) {
		$request_headers = apache_request_headers();
		// Server-side fix for bug in old Android versions (a nice side-effect of this fix means we don't care about capitalization for Authorization).
		$request_headers = array_combine( array_map( 'ucwords', array_keys( $request_headers ) ), array_values( $request_headers ) );
		// print_r($requestHeaders);
		if ( isset( $request_headers['Authorization'] ) ) {
			$headers = trim( $request_headers['Authorization'] );
		}
	}
	return $headers;
}

/**
 * Get access token from header.
 * */
function get_bearer_token( $headers ) {
	// HEADER: Get the access token from the header.
	if ( ! empty( $headers ) ) {
		if ( preg_match( '/Bearer\s((.*)\.(.*)\.(.*))/', $headers, $matches ) ) {
			return $matches[1];
		}
	}
	return null;
}
