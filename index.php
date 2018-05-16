<?php
/**
 * Plugin Name:  JWT Rest API Authentication
 * Plugin URI:   https://github.com/mrbobbybryant/jwt-wp-auth
 * Description:  Plugin modifies the WordPress Rest API to use JWTs to Authenticate API Requests.
 * Version:      0.0.1
 * Author:       Bobby Bryant
 * Author URI:   https://developwithwp.com
 * License:      GPL2
 * License URI:  https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:  jwt-auth
 * Domain Path:  /languages
 *
 * @package JWT Rest API Authentication
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit; // Exit if accessed directly.
}

if ( ! defined( 'JWT_AUTH_VERSION' ) ) {
	define( 'JWT_AUTH_VERSION', '1.0.0' );
}

if ( ! defined( 'JWT_AUTH_PATH' ) ) {
	define( 'JWT_AUTH_PATH', dirname( __FILE__ ) );
}

require_once JWT_AUTH_PATH . '/includes/api.php';
require_once JWT_AUTH_PATH . '/includes/auth.php';
require_once JWT_AUTH_PATH . '/includes/headers.php';
require_once JWT_AUTH_PATH . '/includes/jwt.php';

JWT\API\setup();
JWT\Auth\setup();
JWT\Headers\setup();
