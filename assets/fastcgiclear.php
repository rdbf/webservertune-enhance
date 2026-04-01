<?php
/**
 * Plugin Name: Clear cache after update
 * Description: Clear cache after update
 * Version: 1.0.0
 * Author: rdbf
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

add_action( 'upgrader_process_complete', 'fastcgiclear_set_cache_stale', 10, 2 );

function fastcgiclear_set_cache_stale( $upgrader, $hook_extra ) {
    $home = getenv( 'HOME' );
    if ( ! $home ) {
        return;
    }

    $flag_file = rtrim( $home, '/' ) . '/clear.cache';

    file_put_contents( $flag_file, "cache=stale\n" );
}
