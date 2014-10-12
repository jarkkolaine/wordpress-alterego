<!DOCTYPE html>
<!--[if IE 8]>
<html xmlns="http://www.w3.org/1999/xhtml" class="ie8" <?php language_attributes(); ?>>
<![endif]-->
<!--[if !(IE 8) ]><!-->
<html xmlns="http://www.w3.org/1999/xhtml" <?php language_attributes(); ?>>
<!--<![endif]-->
<head>
	<meta http-equiv="Content-Type" content="<?php bloginfo('html_type'); ?>; charset=<?php bloginfo('charset'); ?>" />
	<title><?php bloginfo('name'); ?> &rsaquo; <?php _e( 'AlterEgo Authentication', 'alterego_login' ); ?></title>
	
	<?php
		wp_admin_css( 'login', true );

		wp_enqueue_script('jquery');
		do_action( 'login_enqueue_scripts' );
		do_action( 'login_head' );

		
		$login_header_url   = __( 'https://wordpress.org/' );
		$login_header_title = __( 'Powered by WordPress' );
				
		$login_header_url = apply_filters( 'login_headerurl', $login_header_url );	
		$login_header_title = apply_filters( 'login_headertitle', $login_header_title );

		$classes = array( 'login-action-' . $action, 'wp-core-ui' );
		if ( wp_is_mobile() ) {
			$classes[] = 'mobile';
		}
		if ( is_rtl() ) {
			$classes[] = 'rtl';
		}
		if ( $interim_login ) {
			$classes[] = 'interim-login';
		}
	?>
	
	<style type="text/css">html{background-color: transparent;}</style>
	<?php
		if ( 'success' ===  $interim_login ) {
			$classes[] = 'interim-login-success';
		}
		$classes[] =' locale-' . sanitize_html_class( strtolower( str_replace( '_', '-', get_locale() ) ) );		
	?>
	
	
</head>
<body class="login <?php echo esc_attr( implode( ' ', $classes ) ); ?>">
	<div id="login">
		<h1><a href="<?php echo esc_url( $login_header_url ); ?>" title="<?php echo esc_attr( $login_header_title ); ?>"><?php bloginfo( 'name' ); ?></a></h1>
		
		<?php
			unset( $login_header_url, $login_header_title );
		?>

		<p class="message" id="sending-notice" style="display:none;">Sending AlterEgo challenge</p>
		<p class="message" id="waiting-notice" style="display:none;">Waiting for you to accept the AlterEgo challenge</p>
		<p class="message" id="login-ok-notice" style="display:none;">Login Successful</p>
		
		<?php if ( isset( $error_message ) ) : ?>
			<div id="login_error" id="alter-ego-error"><?php echo $error_message; ?></div>
		<?php endif; ?>
	
		<form name="loginform" id="loginform" method="post" action="<?php echo esc_url( $alterego_login_url ) ?>">
			<input type="hidden" name="login" value="<?php echo $user->user_login; ?>"/>
			<input type="hidden" name="alterego_sig" value="<?php echo $signature; ?>"/>
			<input type="hidden" name="redirect_to" value="<?php echo $redirect_to; ?>"/>
			<input type="hidden" name="remember_me" value="<?php echo $remember_me; ?>"/>
			
			<label for="alterego_key"><?php _e('Enter AlterEgo Code:', 'alterego_login') ?><br />
			<input type="password" name="alterego_key" class="input" /></label>
				
			<input type="submit" name="wp-submit" id="wp-submit" class="button button-primary button-large" value="<?php esc_attr_e('Log In'); ?>" />
				
			<a href="#" id="send-challenge">Login with phone</a>
		</form>
		

		<p id="backtoblog"><a href="<?php echo esc_url( home_url( '/' ) ); ?>" title="<?php esc_attr_e( 'Are you lost?' ); ?>"><?php printf( __( '&larr; Back to %s' ), get_bloginfo( 'title', 'display' ) ); ?></a></p>
	</div>

	<div class="clear"></div>
	
	<script type="text/javascript" >
		var ajaxurl = "<?php echo admin_url( 'admin-ajax.php' ); ?>";
		var redirectUrl = "<?php echo $redirect_to; ?>";

		/**
		 * Does an AJAX call to check if challenge has been accepted.
		 * If not yet, tries again in 3 seconds.
		 */
		function checkChallenge(id) {		
			var data = {
				'action': 'check_challenge',
				'id': id,
				'login': '<?php echo $user->user_login; ?>',
				'sig': '<?php echo $signature; ?>',
				'remember_me': '<?php echo $remember_me; ?>'			
			};
			jQuery.post(ajaxurl, data, function(res) {
				if (res == true) {
					jQuery("#waiting-notice").hide();
					jQuery("#login-ok-notice").show();
					
					window.location.replace( redirectUrl );
				} else {
					setTimeout(function() { checkChallenge(id); }, 3000);
				}			
			}); 
		}
	
		jQuery(document).ready(function($) {
			jQuery("#send-challenge").click(function() {
				jQuery("#loginform").hide();
				jQuery("#login_error").hide();
				jQuery("#sending-notice").show();
				
				var data = {
					'action': 'send_challenge',
					'login': '<?php echo $user->user_login; ?>',
					'sig': '<?php echo $signature; ?>'
				};

				$.post(ajaxurl, data, function(response) {
					jQuery("#sending-notice").hide();
					jQuery("#waiting-notice").show();
					
					// After 3 seconds, check if challenge has been accepted
					setTimeout( function() { checkChallenge(response); }, 3000 );
				});
			})
		});
	</script>
</body>
</html>