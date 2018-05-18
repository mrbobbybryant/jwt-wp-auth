<?php
namespace JWT\API;

use JWT\JWT;

if ( ! defined( 'ABSPATH' ) ) {
	exit; // Exit if accessed directly.
}

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
			'methods'  => \WP_REST_Server::EDITABLE,
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

	register_rest_route(
		'jwt/v1', '/auth/reset_password', array(
			'methods'             => \WP_REST_Server::EDITABLE,
			'callback'            => __NAMESPACE__ . '\reset_password',
			'permission_callback' => __NAMESPACE__ . '\reset_password_permissions_check',
			'args'                => get_reset_arguments(),
		)
	);

	register_rest_route(
		'jwt/v1', '/auth/change_password', array(
			'methods'             => \WP_REST_Server::EDITABLE,
			'callback'            => __NAMESPACE__ . '\change_password',
			'permission_callback' => __NAMESPACE__ . '\change_password_permissions_check',
			'args'                => get_change_password_arguments(),
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

	/**
	 * Filters the data being returned to the user after creating a new user.
	 *
	 * @since 1.0.0
	 *
	 * @param array $payload The response being returned to the user.
	 * @param array $user An array of user data for the new user.
	 */
	$payload = apply_filters( 'jwt_wp_filter_register_response', $payload, $user );

	/**
	 * Fires immediately after a new user is registered.
	 *
	 * @since 1.0.1
	 *
	 * @param array $user An array of user data for the new user.
	 */
	do_action( 'jwt_wp_after_register_user', $user );

	return rest_ensure_response( $payload );
}

/**
 * Change Password endpoint callback function. Allows an anonymous user to reset their password.
 *
 * @param [Object] $request WP Rest API Request Object.
 * @return Object Success object with Json Web Token, Error if change password fails.
 */
function change_password( $request ) {
	$user = check_password_reset_key( $request['reset_key'], $request['user_login'] );

	$user_data = array(
		'ID'        => $user->ID,
		'user_pass' => $request['password'],
	);

	$updated = wp_update_user( $user_data );

	if ( is_wp_error( $updated ) ) {
		$error = new \WP_Error(
			$updated->get_error_code(),
			$updated->get_error_message(),
			array( 'status' => 401 )
		);

		return rest_ensure_response( $error );
	}

	$jwt       = JWT\create( $user );
	$user_data = get_default_user_data( $user );

	$payload = array_merge( $user_data, $jwt );

	$payload = apply_filters( 'jwt_wp_filter_login_response', $payload, $user );

	return rest_ensure_response( $payload );

}

/**
 * Function checks to make sure the change password request meets certain requirements.
 * - Confirms that the reset_key is valid and as not expired.
 * - Confirms that the user submitted a password and confirmation password.
 * - Confirms that those passwords are equal.
 *
 * @param [Object] $request WP Rest API Request Object.
 * @return Object Success return true, or WP_Error if change password fails.
 */
function change_password_permissions_check( $request ) {

	$user = check_password_reset_key( $request['reset_key'], $request['user_login'] );

	if ( is_wp_error( $user ) ) {
		$error = new \WP_Error(
			$user->get_error_code(),
			$user->get_error_message(),
			array( 'status' => 401 )
		);

		return rest_ensure_response( $error );
	}

	if ( ! $user ) {
		$error = new \WP_Error(
			'user_reset_error',
			'Reset key is not for a valid WP user.',
			array( 'status' => 401 )
		);

		return rest_ensure_response( $error );
	}

	if ( '' === $request['password'] || '' === $request['confirm_password'] ) {
		$error = new \WP_Error(
			'user_reset_error',
			'Reset and Confirmation passwords cannot be empty.',
			array( 'status' => 401 )
		);

		return rest_ensure_response( $error );
	}

	if ( $request['password'] !== $request['confirm_password'] ) {
		$error = new \WP_Error(
			'user_reset_error',
			'Reset and Confirmation passwords do not match.',
			array( 'status' => 401 )
		);

		return rest_ensure_response( $error );
	}

	return true;
}

/**
 * Function defines the arguments schema for the change password enpoint.
 *
 * @return Array Associative array for the login schema.
 */
function get_change_password_arguments() {
	$args = array();

	$args['user_login'] = array(
		'description'       => esc_html__( 'A WordPress username.' ),
		'type'              => 'string',
		'required'          => true,
		'validate_callback' => __NAMESPACE__ . '\string_arg_validate_callback',
	);

	$args['reset_key'] = array(
		'description'       => esc_html__( 'Reset password key which was sent in the reset password email.' ),
		'type'              => 'string',
		'required'          => true,
		'validate_callback' => __NAMESPACE__ . '\string_arg_validate_callback',
	);

	$args['password'] = array(
		'description'       => esc_html__( 'Reset password key which was sent in the reset password email.' ),
		'type'              => 'string',
		'required'          => true,
		'validate_callback' => __NAMESPACE__ . '\string_arg_validate_callback',
	);

	$args['confirm_password'] = array(
		'description'       => esc_html__( 'Reset password key which was sent in the reset password email.' ),
		'type'              => 'string',
		'required'          => true,
		'validate_callback' => __NAMESPACE__ . '\string_arg_validate_callback',
	);

	return $args;
}

/**
 * Callback function responsible for logging a user as requests a password reset link. Function
 * Creates reset key, saves it to the DB, and sends the reset password link via an email.
 *
 * @param [Object] $request WP Rest API Request Object.
 * @return Object|mixed Returns true on success, or an Error if request fails.
 */
function reset_password( $request ) {
	global $wpdb, $wp_hasher, $wp_db_version;

	if ( strpos( $request['user_login'], '@' ) ) {
		$user_data = get_user_by( 'email', trim( $request['user_login'] ) );
	} else {
		$user_data = get_user_by( 'login', trim( $request['user_login'] ) );
	}

	$user_login = $user_data->user_login;
	$user_email = $user_data->user_email;

	// Generate something random for a password reset key.
	$key = wp_generate_password( 20, false );

	if ( empty( $wp_hasher ) ) {
		require_once ABSPATH . WPINC . '/class-phpass.php';
		$wp_hasher = new \PasswordHash( 8, true );
	}
	if ( $wp_db_version >= 32814 ) {
		// 4.3 or later
		$hashed = time() . ':' . $wp_hasher->HashPassword( $key );
	} else {
		$hashed = $wp_hasher->HashPassword( $key );
	}

	$result = $wpdb->update( $wpdb->users, [ 'user_activation_key' => $hashed ], [ 'user_login' => $user_login ] );

	if ( false === $result ) {
		$error = new \WP_Error(
			'jwt_reset_error',
			'Fatal Error. Unable to request a password reset for this user. Please try again.',
			array( 'status' => 401 )
		);

		return rest_ensure_response( $error );
	}

	$email = send_reset_password_email( $user_login, $key, $user_email, $user_data );

	if ( is_wp_error( $email ) ) {
		$error = new \WP_Error(
			$email->get_error_code(),
			$email->get_error_message(),
			array( 'status' => 401 )
		);

		return rest_ensure_response( $error );
	}

	return true;
}

/**
 * Function runs a number of checks to make sure that we have a valid reset password request.
 *
 * @param [Object] $request WP Rest API Request Object.
 * @return Object|mixed Returns true on success, or an Error if request fails.
 */
function reset_password_permissions_check( $request ) {
	if ( strpos( $request['user_login'], '@' ) ) {
		$user_data = get_user_by( 'email', trim( $request['user_login'] ) );

		if ( empty( $user_data ) ) {
			$error = new \WP_Error(
				'jwt_reset_error_email',
				'A user with that email does not exist.',
				array( 'status' => 401 )
			);

			return rest_ensure_response( $error );
		}
	} else {
		$user_data = get_user_by( 'login', trim( $request['user_login'] ) );

		if ( empty( $user_data ) ) {
			$error = new \WP_Error(
				'jwt_reset_error_username',
				'A user with that username does not exist.',
				array( 'status' => 401 )
			);

			return rest_ensure_response( $error );
		}
	}

	$allow = apply_filters( 'allow_password_reset', true, $user_data->ID );

	if ( ! $allow ) {
		$error = new \WP_Error(
			'jwt_reset_error',
			'This website does not allow password resets.',
			array( 'status' => 401 )
		);

		return rest_ensure_response( $error );
	} elseif ( is_wp_error( $allow ) ) {
		$error = new \WP_Error(
			$allow->get_error_code(),
			$allow->get_error_message(),
			array( 'status' => 401 )
		);

		return rest_ensure_response( $error );
	}

	return true;
}

/**
 * Function regestes the only valid argumnets that the reset password endpoint will accept.
 *
 * @return Array Associative array for the login schema.
 */
function get_reset_arguments() {
	$args = array();

	$args['user_login'] = array(
		'description'       => esc_html__( 'A WordPress username.' ),
		'type'              => 'string',
		'required'          => true,
		'validate_callback' => __NAMESPACE__ . '\string_arg_validate_callback',
	);

	return $args;
}

/**
 * Function contains all the logic to actually send the reset password email.
 *
 * @param [string] $user_login WP User Name.
 * @param [string] $key Generated Reset Password Key.
 * @param [string] $user_email WP User Email.
 * @param [object] $user_data WP User Object.
 * @return Object|mixed Returns true on success, or an Error if request fails.
 */
function send_reset_password_email( $user_login, $key, $user_email, $user_data ) {
	$url = add_query_arg(
		array(
			'rcp_action' => 'lostpassword_reset',
			'key'        => $key,
			'login'      => rawurlencode( $user_login ),
		),
		JWT_ORIGIN
	);

	$url = apply_filters( 'retrieve_password_url', $url );

	$message  = esc_html__( 'Someone requested that the password be reset for the following account:', 'jwt' ) . "\r\n\r\n";
	$message .= network_home_url( '/' ) . "\r\n\r\n";
	$message .= sprintf( esc_html__( 'Username: %s', 'jwt' ), $user_login ) . "\r\n\r\n";
	$message .= esc_html__( 'If this was a mistake, just ignore this email and nothing will happen.', 'jwt' ) . "\r\n\r\n";
	$message .= esc_html__( 'To reset your password, visit the following address:', 'jwt' ) . "\r\n\r\n";
	$message .= esc_url_raw( $url ) . "\r\n";

	if ( is_multisite() ) {

		$blogname = $GLOBALS['current_site']->site_name;

	} else {
		/*
		 * The blogname option is escaped with esc_html on the way into the database
		 * in sanitize_option we want to reverse this for the plain text arena of emails.
		 */
		$blogname = wp_specialchars_decode( get_option( 'blogname' ), ENT_QUOTES );
	}

	$title   = sprintf( esc_html__( '[%s] Password Reset', 'jwt' ), $blogname );
	$title   = apply_filters( 'retrieve_password_title', $title );
	$message = apply_filters( 'retrieve_password_message', $message, $key, $user_login, $user_data );

	if ( $message && ! wp_mail( $user_email, wp_specialchars_decode( $title ), $message ) ) {
		return new \WP_Error(
			'jwt_reset_error_email',
			'The e-mail could not be sent, your host may have disabled the mail() function.',
			array( 'status' => 401 )
		);
	}

	return true;
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

	$args = apply_filters( 'jwt_wp_filter_register_args', $args );

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
