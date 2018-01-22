<?php
namespace JWT\API;

use JWT\JWT;

function setup() {
	add_action( 'rest_api_init', __NAMESPACE__ . '\register_user_auth_route' );
}

function register_user_auth_route() {
	register_rest_route(
		'archsystems/v1', '/auth/login', array(
			'methods'  => \WP_REST_Server::READABLE,
			'callback' => __NAMESPACE__ . '\authorize_user',
		)
	);

	register_rest_route(
		'archsystems/v1', '/auth/register', array(
			'methods'  => \WP_REST_Server::EDITABLE,
			'callback' => __NAMESPACE__ . '\register_user',
		)
	);
}

function make_public() {
	return true;
}


function authorize_user( $request ) {
	$parameters = $request->get_params();

	$user = wp_authenticate( $parameters['username'], $parameters['password'] );

	if ( is_wp_error( $user ) ) {
		// $error = new \WP_Error(
		// 	$user->code,
		// 	$user->message,
		// 	array( 'status' => 401 )
		// );

		$response = new \WP_REST_Response( $user );
    	$response->header( 'Access-Control-Allow-Origin', '*' );
    	return $response;
	}

	$response = new \WP_REST_Response( JWT\create( $user ) );
    $response->header( 'Access-Control-Allow-Origin', '*' );
    return $response;
}

function register_user( $request ) {
	$parameters = $request->get_params();

	if ( ! \get_option( 'users_can_register' ) ) {
		return new \WP_Error(
			'omg_entries_login_required',
			esc_html__( 'Sorry, you must allow users to signup for this endpoint to work.', 'archsystems' ),
			array( 'status' => 401 )
		);
	}

	$user = wp_create_user( $parameters['username'], $parameters['password'], $parameters['email'] );

	if ( is_wp_error( $user ) ) {
		$code = $user->get_error_code();
		return new \WP_Error(
			$code,
			$user->get_error_message( $code ),
			array( 'status' => 401 )
		);
	}

	$user = get_userdata( $user );

	return wp_send_json_success( JWT\create( $user ) );
}
