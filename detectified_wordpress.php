<?php
/*
 * Plugin Name: Detectifed Wordpress
 * Description: Address findings discovered by Detectify scan
 */
//echo ('<pre>');
//var_dump($_REQUEST); die();
//echo ('</pre>');

// Prevent executing this file directly
if ( !defined( 'ABSPATH' ) ) exit;

/*
 * Disable users REST end points
 * Inspired by https://github.com/WP-API/WP-API/issues/2338#issuecomment-193887183
 */
add_filter( 'rest_endpoints', function( $endpoints ){
    $disable_rest_endpoints = [ '/wp/v2/users', '/wp/v2/users/(?P<id>[\d]+)', '/wp/v2/users/me' ];
    foreach( $disable_rest_endpoints as $key ) {
        if ( isset( $endpoints[$key] ) ) { unset( $endpoints[$key] ); }
    }
    return $endpoints;
});

/*
 * Nonce on login
 * Inspired by https://github.com/elyobo/wp-login-nonce
 */
// Add nonce to login form
add_action( 'login_form', function() {
    wp_nonce_field('_dw_anti_csrf_login' . $_SERVER['REMOTE_ADDR'], 'dw_login_token');
});
// Validate form nonce
function detectified_wordpress_validate_login_nonce ( $user, $username, $password ) {
    if ( empty( $_POST ) ) { return; }
    if ( ! empty( $user ) ) { return; }
    $error_message = '';
    if ( ! isset( $_POST['dw_login_token'] ) ) {
        $error_message = '<strong>ERROR</strong>: Nonce not provided. Try again.';
    } elseif ( ! wp_verify_nonce( $_POST['dw_login_token'], '_dw_anti_csrf_login' . $_SERVER['REMOTE_ADDR'] ) ) {
        $error_message = '<strong>ERROR</strong>: Nonce invalid. Try again.';
    }
    if ( $error_message != '' ) {
        remove_action( 'authenticate' , 'wp_authenticate_username_password', 20 );
        return new WP_Error( 'denied', __($error_message) );
    }
}
add_filter( 'authenticate', 'detectified_wordpress_validate_login_nonce', 10, 3 );

// Limit nonce timeout if on a login/register page
if (isset( $GLOBALS['pagenow'] ) 
    && in_array( $GLOBALS['pagenow'], array( 'wp-login.php', 'wp-register.php' ) )
    && ( empty( $_GET['action']) || $_GET['action'] != 'logout' )
    ) {
    add_filter( 'nonce_life', function() { return 600; } );
    add_action( 'login_head', function() {
        echo( '<meta http-equiv="refresh" content="300">' );
    });
}

/*
 * Nonce on comment forms
 * Inspired by https://www.narga.net/stop-wordpress-spam-comments-trackbracks/
 * and http://www.daharveyjr.com/fighting-wordpress-comment-spam-with-a-nonce/
 */
add_action( 'comment_form', function() {
    wp_nonce_field('_dw_anti_csrf_comment', 'dw_comment_token');
});
add_action( 'pre_comment_on_post', function () {
    if ( ! isset( $_REQUEST['dw_comment_token'] ) || ! wp_verify_nonce( $_REQUEST['dw_comment_token'], '_dw_anti_csrf_comment' ) ) {
        $error_html = '<strong>ERROR</strong>: Comment nonce invalid.';
        $title = get_bloginfo( 'name' );
        if ( isset( $_REQUEST['comment_post_ID'] ) && ( $post_id = intval( $_REQUEST['comment_post_ID'] ) ) && ( $link = get_permalink( $post_id ) ) ) {
                $title = get_the_title( $post_id );
            if ( isset ( $_REQUEST['comment_parent'] ) && ( $comment_parent_id = intval( $_REQUEST['comment_parent'] ) ) ) {
                $link .= '#comment-' . $comment_parent_id;
            }
        } else {
            $link = site_url();
        }
        $error_html .= '<br /><a href="' . $link . '" title="' . esc_attr( $title ) . '">' . $title . '</a>';
        wp_die($error_html);
    }
}, 10 );

