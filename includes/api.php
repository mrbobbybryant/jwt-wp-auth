<?php
namespace JWT\API;

use JWT\JWT;

/**
 * Function bootstraps the JWT endpoint functionality.
 *
 * @return void
 */
function setup() {
	add_action( 'rest_api_init', __NAMESPACE__ . '\register_user_auth_route' );
}

/**
 * Function registers the JWT APi Endpoints. These endpoints provide a way for
 * users to login with their WP Username and password. Also provides an endpoint
 * which allows public user signups.
 *
 * @return void
 */
function register_user_auth_route() {
	register_rest_route(
		'jwt/v1', '/auth/login', array(
			'methods'  => \WP_REST_Server::READABLE,
			'callback' => __NAMESPACE__ . '\authorize_user',
			'args'     => get_login_arguments(),
		)
	);

	register_rest_route(
		'jwt/v1', '/auth/register', array(
			'methods'             => \WP_REST_Server::EDITABLE,
			'callback'            => __NAMESPACE__ . '\register_user',
			'permission_callback' => __NAMESPACE__ . '\register_user_permissions_check',
			'args'                => get_register_arguments(),
		)
	);
}

/**
 * Login endpoint callback. Handles logging a user in via their WordPress Username
 * and password.
 *
 * @param [Object] $request WP Rest API Request Object.
 * @return Object|WP_Error Success object with Json web token, Error if user login failed.
 */
function authorize_user( $request ) {
	$parameters = $request->get_params();

	$user = wp_authenticate( $parameters['username'], $parameters['password'] );

	if ( is_wp_error( $user ) ) {
		$error = new \WP_Error( $user->get_error_code(), $user->get_error_message(), array( 'status' => 401 ) );
		return rest_ensure_response( $error );
	}

	$jwt       = JWT\create( $user );
	$user_data = get_default_user_data( $user );

	$payload = array_merge( $user_data, $jwt );

	$payload = apply_filters( 'jwt_wp_filter_login_response', $payload, $user );

	return rest_ensure_response( $payload );
}

/**
 * Register endpoint callback function. Handles create a new user.
 *
 * @param [Object] $request WP Rest API Request Object.
 * @return Object Success object with Json web token, Error if user signup failed.
 */
function register_user( $request ) {
	$parameters = $request->get_params();

	$user = wp_create_user( $parameters['username'], $parameters['password'], $parameters['email'] );

	if ( is_wp_error( $user ) ) {
		$error = new \WP_Error(
			$user->get_error_code(),
			$user->get_error_message(),
			array( 'status' => 401 )
		);

		return rest_ensure_response( $error );
	}

	$jwt  = JWT\create( $user );
	$user = get_default_user_data( get_userdata( $user ) );

	$payload = array_merge( $jwt, $user );
	$payload = apply_filters( 'jwt_wp_filter_register_response', $payload, $user );

	return rest_ensure_response( $payload );
}

/**
 * Function checks to make sure that new user signs are allowed.
 *
 * @return WP_Error|boolean error if user signups are not allowed. Otherwise function returns true.
 */
function register_user_permissions_check() {
	if ( ! \get_option( 'users_can_register' ) ) {
		$error = new \WP_Error(
			'jwt_login_required',
			esc_html__( 'Sorry, you must allow users to signup for this endpoint to work. Go to Settings -> General.' ),
			array( 'status' => 401 )
		);

		return rest_ensure_response( $error );
	}
	return true;
}

/**
 * Login Endpoint Arguments Schema. Function ensures that all required args are present.
 * Function also validates those arguments based on the schema.
 *
 * @return Array Associative array for the login schema.
 */
function get_login_arguments() {
	$args = array();

	$args['username'] = array(
		'description'       => esc_html__( 'A WordPress username.' ),
		'type'              => 'string',
		'required'          => true,
		'validate_callback' => __NAMESPACE__ . '\string_arg_validate_callback',
	);

	$args['password'] = array(
		'description'       => esc_html__( 'A WordPress password.' ),
		'type'              => 'string',
		'required'          => true,
		'validate_callback' => __NAMESPACE__ . '\string_arg_validate_callback',
	);

	return $args;
}

/**
 * Register Endpoint Arguments Schema. Function ensures that all required args are present.
 * Function also validates those arguments based on the schema.
 *
 * @return Array Associative array for the register schema.
 */
function get_register_arguments() {
	$args = array();

	$args['username'] = array(
		'description'       => esc_html__( 'A WordPress username.' ),
		'type'              => 'string',
		'required'          => true,
		'validate_callback' => __NAMESPACE__ . '\string_arg_validate_callback',
		'sanitize_callback' => __NAMESPACE__ . '\string_arg_sanitize_callback',
	);

	$args['email'] = array(
		'description'       => esc_html__( 'A WordPress username.' ),
		'type'              => 'string',
		'required'          => true,
		'validate_callback' => __NAMESPACE__ . '\string_arg_validate_callback',
		'sanitize_callback' => __NAMESPACE__ . '\email_arg_sanitize_callback',
	);

	$args['password'] = array(
		'description'       => esc_html__( 'A WordPress username.' ),
		'type'              => 'string',
		'required'          => true,
		'validate_callback' => __NAMESPACE__ . '\string_arg_validate_callback',
		'sanitize_callback' => __NAMESPACE__ . '\string_arg_sanitize_callback',
	);
	return $args;
}

/**
 * Function is used to validate all string argument.
 *
 * @param [string] $value User submitted arg.
 * @param [object] $request WP REST API Request Object.
 * @param [string] $param Argument name.
 * @return WP_Error|void
 */
function string_arg_validate_callback( $value, $request, $param ) {
	if ( ! is_string( $value ) ) {
		$error = new \WP_Error(
			'rest_invalid_param',
			sprintf( 'The %s argument must be a string.', $param ),
			array( 'status' => 400 )
		);

		return rest_ensure_response( $error );
	}
}

/**
 * Function is used to sanitize all user submitted string argument prior to making
 * and database calls.
 *
 * @param [string] $value User submitted arg.
 * @param [object] $request WP REST API Request Object.
 * @param [string] $param Argument name.
 * @return string
 */
function string_arg_sanitize_callback( $value, $request, $param ) {
	return sanitize_text_field( $value );
}

/**
 * Function is used to sanitize all user submitted email argument prior to making
 * and database calls.
 *
 * @param [string] $value User submitted arg.
 * @param [object] $request WP REST API Request Object.
 * @param [string] $param Argument name.
 * @return string
 */
function email_arg_sanitize_callback( $value, $request, $param ) {
	return sanitize_email( $value );
}

/**
 * Function filters the WP User Object returned from calling wp_authenticate to
 * only allow some of those values to be passed to the client.
 *
 * @param [object] $user WP User Object.
 * @return array
 */
function get_default_user_data( $user ) {
	return [
		'ID'            => $user->data->ID,
		'user_login'    => $user->data->user_login,
		'user_nicename' => $user->data->user_nicename,
		'user_email'    => $user->data->user_email,
		'roles'         => $user->roles,
	];
}
