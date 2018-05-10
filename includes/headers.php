<?php
namespace JWT\Headers;

if ( ! defined( 'ABSPATH' ) ) {
	exit; // Exit if accessed directly.
}

/**
 * Function handles bottstrapping the headers process.
 *
 * @return void
 */
function setup() {
	add_action( 'rest_api_init', __NAMESPACE__ . '\wp_rest_allow_all_cors', 15 );
	add_filter( 'rest_post_dispatch', __NAMESPACE__ . '\wp_pre_flight_all_cors' );
}

/**
 * Function overrides the default rest cors process and adds our own cors requirements.
 *
 * @return void
 */
function wp_rest_allow_all_cors() {
	$origin = defined( 'JWT_ORIGIN' ) && JWT_ORIGIN ? JWT_ORIGIN : '*';

	remove_filter( 'rest_pre_serve_request', 'rest_send_cors_headers' );

	add_filter( 'rest_pre_serve_request', function( $value ) use ( $origin ) {
		header( sprintf( 'Access-Control-Allow-Origin: %s', $origin ) );
		header( 'Access-Control-Allow-Methods: POST, GET, OPTIONS, PUT, DELETE' );
		header( 'Access-Control-Allow-Credentials: true' );
		return $value;
	});
}

/**
 * Function handles setting CORS for the pre-flight checks that some browser make prior to sending
 * their actual request.
 *
 * @param object $result WP_REST_Response Object.
 * @return object
 */
function wp_pre_flight_all_cors( $result ) {
	if ( isset( $_SERVER['REQUEST_METHOD'] ) && 'OPTIONS' === $_SERVER['REQUEST_METHOD'] ) {
		$result->header( 'Access-Control-Allow-Headers', 'Authorization, Content-Type', true );
	}
	return $result;
}

/**
 * Function handles extracting the Authorization headers from the Request Headers. This
 * is used to the json web token authorization process.
 * */
function get_authorization() {
	$headers = null;
	if ( isset( $_SERVER['Authorization'] ) ) {
		$headers = trim( $_SERVER['Authorization'] );
	} elseif ( isset( $_SERVER['HTTP_AUTHORIZATION'] ) ) {
		$headers = trim( $_SERVER['HTTP_AUTHORIZATION'] );
	} elseif ( function_exists( 'apache_request_headers' ) ) {
		$request_headers = apache_request_headers();
		$request_headers = array_combine( array_map( 'ucwords', array_keys( $request_headers ) ), array_values( $request_headers ) );
		if ( isset( $request_headers['Authorization'] ) ) {
			$headers = trim( $request_headers['Authorization'] );
		}
	}
	return $headers;
}

/**
 * Function attempls to find the Bearer Token in the Authorization header. If found,
 * this function will return the JWT it finds or null if no JWT is found.
 *
 * @param [string] $headers Authorization Header.
 * @return void|string
 */
function get_bearer_token( $headers ) {
	// HEADER: Get the access token from the header.
	if ( ! empty( $headers ) ) {
		if ( preg_match( '/Bearer\s((.*)\.(.*)\.(.*))/', $headers, $matches ) ) {
			return $matches[1];
		}
	}
	return null;
}
