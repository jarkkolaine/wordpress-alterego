<?php
/*
Plugin Name: AlterEgo Two-Factor Authenticator
Description: A plugin that adds <a href="http://alteregoapp.com">AlterEgo</a> authentication to your WordPress web site.
Author: Jarkko Laine
Version: 1.0
Author URI: http://jarkkolaine.com/
*/

/*
Still missing: 
- Some error handling
- Generating the secure token
- Require cURL (make the plugin die gracefully if not present)
 */

class AlterEgo_Login_Plugin {

	//
	// Variables to be used as "constants" throughout the plugin
	//
	
	protected $api_endpoint = 'https://alteregoapp.com/api/';
	protected $alterego_auth_meta_field_name = 'alterego_auth_key';
	protected $alterego_sig_meta_field_name = 'alterego_tmp_signature';
	protected $alterego_token_meta_field_name = 'alterego_tmp_token';

	/**
	 * Sets up the plugin by hooking it to the right WordPress
	 * actions and filters.
	 */	
	public function __construct() {		

		// Authentication process
		
		add_filter( 'authenticate', array( $this, 'authenticate' ), 10, 3 );
						
		add_action( 'wp_ajax_nopriv_send_challenge', array($this, 'ajax_send_challenge'));
		add_action( 'wp_ajax_nopriv_check_challenge', array($this, 'ajax_check_challenge'));

		add_filter( 'query_vars', array( $this, 'add_query_vars' ), 0 );
		add_action( 'parse_request', array($this, 'sniff_alterego_requests'), 0);
		
		// Admin menus for configuring the AlterEgo authentication
		
		add_action( 'admin_init', array( $this, 'register_admin_settings' ) );
		add_action( 'show_user_profile', array( $this, 'register_profile_page_field' ) );
	}

	/**
	 * Authentication implementation with AlterEgo support. 
	 *
	 * This method gets called through the "authenticate" filter hook. 
	 *
	 * If the user has enabled AlterEgo, the login is handled here with an
	 * added AlterEgo step. Otherwise, the process is passed to the 
	 * regular WordPress authentication.
	 */
	function authenticate( $user = '', $username = '', $password = '' ) {	
		if ( $this->get_user_auth_key( $user, $username ) ) {			
			
			// Verify that the user's AlterEgo key is still valid and in use
			$ping = $this->alterego_api_call( get_user_by( 'login', $username ), '/check/ping.json' );
			if ( $ping != 'PONG!') {		
				$this->disable_alter_ego_auth( get_user_by( 'login', $username ) );	
				return $user;				
			}
			
			// Then do the authentication manually
        	$user = wp_authenticate_username_password( $user, $username, $password );
	        if ( is_wp_error( $user ) ) {
	            return $user;
	        }
			
			// Create a temporary signature (valid for 5 minutes), store it in user 
			// meta data and pass as a parameter in the login form. This signature
			// will be checked at the end of the authentication process to make sure the user
			// has passed the regular authentication and is allowed to do the AlterEgo 
			// authentication.
			
			$signature = $this->generate_random_token();
			$this->set_temp_signature( $user, $signature, 'login' );
															
			$this->render_alterego_login_page( $user );
			exit;
		} else {
			// The user is not using AlterEgo, let WordPress handle the login
			return $user;
		}
	}

	/**
	 * Renders the AlterEgo login page with all required user information.
	 *
	 * @uses login_page.php
	 */	
	function render_alterego_login_page( $user, $error = null ) {
     	if ( !($user instanceof WP_User) ) {
    		return;
    	}

		$alterego_login_url = home_url( 'index.php?alterego_login=1' );
		$signature_meta = get_user_meta( $user->ID, $this->alterego_sig_meta_field_name, true );
		
		$signature = '';
		if ( is_array( $signature_meta ) ) {		
			$signature = $signature_meta['signature'];
		}
		
		// Forward WordPress's cookie related parameters
		$redirect_to = $_POST['redirect_to'];
		$remember_me = $_POST['remember_me'];
		
		$error_message = $error;
		
		require( 'login_page.php' );
	}

	/**
	 * Checks the AlterEgo passcode entered by user to finish the login.
	 *
	 * Called by sniff_alterego_requests when it finds an AlterEgo login request.
	 */
	function do_alterego_authentication( $user, $username, $password, $signature ) {								
		if ( !$this->verify_temp_signature( $user, $signature ) ) {
			// Bad or missing signature. Start over.
			wp_redirect( home_url( 'wp-login.php' ) ); 
			exit;
		}
			
		if ( $password == null || trim( $password ) == '' ) {		
			$this->render_alterego_login_page( $user, __( 'AlterEgo code cannot be empty', 'alterego_login' ) );
			exit; 
		}
		
		// Parameters OK, do the login.
		$response = $this->alterego_api_call( $user, 'check/password.json', array( 'pass' => $password ) );
		if ( $response == true ) {
			// AlterEgo code OK, finish login							
			$this->delete_temp_signature( $user, 'login' );
				
			$remember_me = ( $_POST['remember_me'] == 'forever' ) ? true : false;
            wp_set_auth_cookie( $user->ID, $remember_me );
		
			// If redirect was set in parameters, use that one. Otherwise go to Dashboard.			
			$redirect_to = ( isset( $_POST['redirect_to'] ) ) ? $_POST['redirect_to'] : admin_url();
			wp_safe_redirect( $redirect_to );                
		} else {
			$this->render_alterego_login_page( $user, __( 'Invalid AlterEgo code', 'alterego_login' ) );
		}								
	}

	/**
	 * Pushes a new AlterEgo challenge to the user's mobile phone.
	 */
	function ajax_send_challenge() {
		$signature = $_POST['sig'];
		$username = $_POST['login'];
		$user = get_user_by( 'login', $username );
				
		// Verify the signature passed with the AJAX request
		if ( $this->verify_temp_signature( $user, $signature ) ) {
			$challenge_id = $this->alterego_api_call( $user, 'challenge/new.json' );					
    	    echo $challenge_id;
    	} else {
    		echo '-1';
    	}
    	
		die();
	}
	
	/**
	 * Polls AlterEgo to see if authentication challenge has been accepted.
	 */
	function ajax_check_challenge() {
		$signature = $_POST['sig'];
		$challenge_id = $_POST['id'];
		$remember_me = $_POST['remember_me'];
		
		$username = $_POST['login'];		
		$user = get_user_by( 'login', $username );
		
		if ( $this->verify_temp_signature( $user, $signature ) ) {				
			$response = $this->alterego_api_call( $user, 'challenge/check.json', array( 'id' => $challenge_id ) );
			
			if ( $response == 1 ) {		
				// AlterEgo challenge OK, finish login							
				$this->delete_temp_signature( $user, 'login' );
				
				$remember_me = ($remember_me == 'forever') ? true : false;
                wp_set_auth_cookie( $user->ID, $remember_me );
			}
		
			echo $response;
		} else {
			echo '-1';
		}
		
		die();
	}		
	
	//
	// Helper methods, utilities and settings pages
	//

	/**
	 * Makes a call to the AlterEgo API using cURL.
	 *
	 * @param User $user 		The WordPress user object making the call
	 * @param string $method	The API method to call
	 * @param Array $params		The parameters to be sent to the API
	 *
	 * @return the API call response as parsed from JSON
	 */
	function alterego_api_call( $user, $method, $params = array() ) {
		// 'key' is used in every API call, so it's easiest to add it here
		$params['key'] = $this->get_user_auth_key( $user );
    	$url = $this->api_endpoint . $method . '?key=' . $this->get_user_auth_key( $user );

		$params_as_json = json_encode( $params );

		$ch = curl_init();		
		if ( $ch ) {						
			curl_setopt_array(
    			$ch, array( 
	    			CURLOPT_URL => $url,
		    		CURLOPT_RETURNTRANSFER => true,
					CURLOPT_CUSTOMREQUEST => "POST",
					CURLOPT_POSTFIELDS => $params_as_json,
					CURLOPT_HTTPHEADER => array(                                                                          
						'Content-Type: application/json',                                                                                
						'Content-Length: ' . strlen( $params_as_json )
					)
				)
			);
			 			
			$output = curl_exec( $ch );	
			
			if ( $output) {
	    		$json_data = json_decode( $output, true );
		    }	    

			curl_close( $ch );
		} 
			
		return $json_data;
	}
	
	/**
	 * Retrieves the user's AlterEgo authorization key from user metadata. If a user
	 * hasn't linked his/her account to AlterEgo, the key is empty.
	 *
	 * If the method is called without $user, $username is used to look up the 
	 * user from WordPress's database. Finally, if both are null, the method tries to 
	 * look for the currently logged in user.
	 *
	 * @param User $user		The WordPress user object
	 * @param string $username	The user's user name
	 *
	 * @return An AlterEgo key or null if the user hasn't enabled AlterEgo
	 */
	function get_user_auth_key( $user = null, $username = '' ) {
		if ( $user == null ) {
			if ( $username != '' ) {
				$user = get_user_by( 'login', $username );
			} else {
				$user = wp_get_current_user();
			}
		}
		
		return get_user_meta( $user->ID, $this->alterego_auth_meta_field_name, true );	
	}
	
	/**
	 * Adds new query variables to WordPress so that we can catch AlterEgo 
	 * authentication requests in "sniff_alterego_requests".
	 *
	 * @param Array $vars	Current query variables
	 *
	 * @return The $vars array with our added variables.
	 */
	public function add_query_vars($vars){
		$vars[] = 'alterego_login';
		$vars[] = 'alterego_key';
		$vars[] = 'alterego_sig';
		$vars[] = 'alterego_setup';
		$vars[] = 'alterego_notice';
		
		return $vars;
	}

	/**	
	 * Listens to HTTP requests, captures the AlterEgo specific requests and
	 * passes them to the correct handlers.
	 */
	public function sniff_alterego_requests() {
		global $wp;
		
		// AlterEgo login requests ("alterego_login")
		
		if ( isset( $wp->query_vars['alterego_login'] ) ) {
			$password = $wp->query_vars['alterego_key'];
			$signature = $wp->query_vars['alterego_sig'];
			
			$username = $_POST['login'];
			$user = get_user_by( 'login', $username );
			
			$this->do_alterego_authentication( $user, $username, $password, $signature );
			exit;
		}
		
		// Enabling / disabling AlterEgo authentication ("alterego_setup")
		
		if ( isset( $wp->query_vars['alterego_setup'] ) ) {
			if ( is_user_logged_in() ) {			
				$user = wp_get_current_user();			
				switch ( $wp->query_vars['alterego_setup'] ) {
					// Step 1: start enabling process
					case 1:		
						$this->redirect_to_alterego( $user );
						exit;
						break;
				
					// Step 2: verify and save data from AlterEgo
					case 2:
						$this->alter_ego_auth_callback( $user );
						exit;
						
					// Disable AlterEgo
					case 3:
						$this->disable_alter_ego_auth( $user );
						wp_redirect( admin_url( 'profile.php?updated=1' ) );
						exit;
				
					default:
						break;
				}
			} else {
				// User not logged in, cannot enable / disable AlterEgo
				wp_redirect( home_url() );
			}
		}		
	}
	
	/** 
	 * Generates a random token for use in temporary signatures.
	 */
	function generate_random_token() {
		return bin2hex(openssl_random_pseudo_bytes(16));
	}

	/** 
	 * Saves a temporary signature a time stamp to user's meta data. The same method 
	 * is used for both the login signature (type 'login') and the signature used 
	 * in enabling AlterEgo authentication (type 'auth-token').
	 *
	 * @param	User $user			WordPress user object
	 * @param 	string $signature	The signature to store into user metadata
	 * @param	string $type		The type of the signature ("login" / "auth-token")
	 */
	function set_temp_signature( $user, $signature, $type = 'login' ) {	
		if ( $type == 'login' || $type == 'auth-token' ) {
			// Pick the right data field
			if ($type == 'login') {
				$field_name = $this->alterego_sig_meta_field_name;
			} else {
				$field_name = $this->alterego_token_meta_field_name;
			}
			
			update_user_meta( $user->ID, $field_name, array( 'signature' => $signature, 'time' => time() ) );
		}
	}

	/**
	 * Checks that the submitted temporary signature matches with the one saved in user
	 * data and is not expired.
	 *
	 * @param User $user		WordPress user object
	 * @param string $signature	Submitted signature
	 *
	 * @return true if signature is valid. Otherwise false.
	 */
	function verify_temp_signature( $user, $signature, $type = 'login' ) {
		$signature_meta = null;
		if ( $type == 'login' ) {
			$signature_meta = get_user_meta( $user->ID, $this->alterego_sig_meta_field_name, true );		
		} else {
			$signature_meta = get_user_meta( $user->ID, $this->alterego_token_meta_field_name, true );		
		}
		
		if ( !is_array( $signature_meta ) ) {
			return false;
		}

		$verify_signature = $signature_meta['signature'];
		$signature_time = $signature_meta['time'];		
		$five_minutes = 5 * 60;								
				
		// Check that signatures match and the signature in user meta isn't older than 5 minutes
		if ( ( $verify_signature == $signature ) && ( time() <= ( $signature_time + $five_minutes ) ) ) {
			return true; 
		} else {
			return false;
		}
	}
	
	/**
	 * Deletes the temporary signature. Should be called when the signature has been
	 * checked and is no longer needed.
	 *
	 * @param User $user		The user whose signature should be removed
	 * @param string $type		The type of the signature ('login' / 'auth-token')
	 */
	function delete_temp_signature( $user, $type ) {		
		if ( $type == 'login' || $type == 'auth-token' ) {
			// Pick the right data field
			if ($type == 'login') {
				$field_name = $this->alterego_sig_meta_field_name;
			} else {
				$field_name = $this->alterego_token_meta_field_name;
			}

			delete_user_meta( $user->ID, $field_name );
		}
	}

	/**
	 * Adds a General Settings field for storing the AlterEgo API key.
	 */		
	function register_admin_settings() {
		add_settings_field(
			'alterego_api_key',
			'AlterEgo API key',
			array( $this, 'alterego_api_key_setting_callback' ),
			'general'
		);		
		register_setting( 'general', 'alterego_api_key' );	
	}

	/** 
	 * Callback function for rendering the API key settings field.
	 */
 	function alterego_api_key_setting_callback() {
 		echo '<input name="alterego_api_key" type="text" class="regular-text" value="' . get_option( 'alterego_api_key' ) . '"/>';
	}
			
	/**
	 * Renders the profile page option for enabling AlterEgo authentication for 
	 * the currently logged in user.
	 *
	 * @param User $user	Current user's WordPress user object
	 */
	function register_profile_page_field( $user ) {
	?>
		<table class="form-table">
		<tr>
			<th>
				<label for="alterego_enabled"><?php _e( 'AlterEgo Authentication', 'alterego_login' ); ?></label>
			</th>
			<td>
				<?php if ( $this->get_user_auth_key( $user, $username ) ) :	?>
					<p>
						<?php _e( 'AlterEgo two-factor authentication <strong>enabled</strong>.', 'alterego_login' ); ?>
						<a href="<?php echo home_url( 'index.php?alterego_setup=3' ); ?>"><?php _e( 'Disable', 'alterego_login' ); ?></a>
					</p>
				<?php else : ?>
					<p>
						<a href="<?php echo home_url( 'index.php?alterego_setup=1' ); ?>">
							<?php _e( 'Enable AlterEgo two-factor authentication', 'alterego_login' ); ?>
						</a>
					</p>
				<?php endif; ?>						
			</td>
		</tr>
		</table>
	<?php
	}
	 
	/**
	 * Starts the process of setting up the AlterEgo authentication for current user:
	 * redirects the user to AlterEgo to allow our application to use his/her
	 * AlterEgo account.
	 */
	function redirect_to_alterego( $user ) {
		$app_id = get_option( 'alterego_api_key' );
		
		// Create temporary token and store it in user data
		$token = $this->generate_random_token();
		$this->set_temp_signature( $user, $token, 'auth-token' );

		// The token is also included in the redirect url to check when user gets back from AlterEgo			
		$redirect_url = urlencode( home_url( 'index.php?alterego_setup=2&token=' . $token, 'https' ) );

		$url = 'https://alteregoapp.com/account/authorize-app?id=' . $app_id . '&redirect_url=' . $redirect_url;
		wp_redirect( $url );
		exit;
	}
	
	/**
	 * Receives and stores (if all is OK) the authorization token sent by AlterEgo
	 * after the user has accepted the request.
	 */
	function alter_ego_auth_callback( $user ) {		
		$token = $_POST['token'];		
		$key = $_POST['key'];			
		
		if ( $this->verify_temp_signature( $user, $token, 'auth-token' ) ) {		
			update_user_meta( $user->ID, $this->alterego_auth_meta_field_name, $key );			
			$this->delete_temp_signature( $user, 'auth-token' );
			
			wp_safe_redirect( admin_url( 'profile.php?updated=1' ) );
			exit;
		} else {
			wp_die( __( 'Invalid security token', 'alterego_login' ) );
		}		
	}
	
	/**
	 * Disables AlterEgo authentication for the given user.
	 */
	function disable_alter_ego_auth( $user ) {
		delete_user_meta( $user->ID, $this->alterego_auth_meta_field_name );
	}

}

new AlterEgo_Login_Plugin();