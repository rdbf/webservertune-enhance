<?php

/**
 * Plugin Name: Clear cache after update
 * Description: Clears Nginx FastCGI cache on plugin/theme/core updates and on
 *              content changes (publishing/editing posts & pages, comments).
 * Version: 1.1.0
 * Author: rdbf
 */

if (! defined('ABSPATH') || ! function_exists('add_action')) {
    exit;
}

/**
 * Write the cache=stale flag the fastcgiclear daemon watches for.
 * Cheap and idempotent — the daemon debounces, so firing it often is fine.
 */
function fastcgiclear_set_cache_stale()
{
    $home = getenv('HOME');

    // Fallback to POSIX system user home directory if HOME env is not set
    if (empty($home) && function_exists('posix_getpwuid') && function_exists('posix_getuid')) {
        $user_info = posix_getpwuid(posix_getuid());
        if (! empty($user_info['dir'])) {
            $home = $user_info['dir'];
        }
    }

    if (empty($home)) {
        return;
    }

    $flag_file = rtrim($home, '/') . '/clear.cache';

    // Verify directory or file is writable before writing to prevent notices
    $dir = dirname($flag_file);
    if (is_writable($dir) || (file_exists($flag_file) && is_writable($flag_file))) {
        @file_put_contents($flag_file, "cache=stale\n");
    }
}

/* -------------------------------------------------------------------------
 * Updates (original behaviour)
 * ---------------------------------------------------------------------- */
add_action('upgrader_process_complete', 'fastcgiclear_set_cache_stale', 10, 0);

/* -------------------------------------------------------------------------
 * Posts & pages — publish, edit, trash, delete
 * ---------------------------------------------------------------------- */

/**
 * Fires on any post status transition (publish, update, trash, etc.).
 * Skips autosaves, revisions, auto-drafts, and non-public post types so we
 * don't purge on irrelevant background activity.
 *
 * @param string   $new_status The new post status.
 * @param string   $old_status The old post status.
 * @param \WP_Post $post       The post object.
 */
function fastcgiclear_on_post_transition($new_status, $old_status, $post)
{
    if (wp_is_post_revision($post) || wp_is_post_autosave($post)) {
        return;
    }
    if ('auto-draft' === $new_status && 'auto-draft' === $old_status) {
        return;
    }

    $post_type = get_post_type($post);
    if ($post_type && ! is_post_type_viewable($post_type)) {
        return;
    }

    // Purge when something becomes (or stops being) publicly visible,
    // or when an already-published item is edited.
    if ('publish' === $new_status || 'publish' === $old_status) {
        fastcgiclear_set_cache_stale();
    }
}
add_action('transition_post_status', 'fastcgiclear_on_post_transition', 10, 3);

// Permanent deletion of a published item.
add_action('delete_post', 'fastcgiclear_set_cache_stale', 10, 0);

/* -------------------------------------------------------------------------
 * Comments — new, edited, or status change (approve / spam / trash)
 * ---------------------------------------------------------------------- */

/**
 * Only purge for comments that are (or are becoming) approved and therefore
 * visible on the page. Avoids purging for comments sitting in moderation/spam.
 *
 * @param int        $comment_id       The comment ID.
 * @param int|string $comment_approved 1 if approved, 0 if not, or approval status.
 */
function fastcgiclear_on_comment_post($comment_id, $comment_approved)
{
    if (1 === $comment_approved || '1' === $comment_approved || 'approve' === $comment_approved) {
        fastcgiclear_set_cache_stale();
    }
}
add_action('comment_post', 'fastcgiclear_on_comment_post', 10, 2);

add_action('edit_comment', 'fastcgiclear_set_cache_stale', 10, 0);

/**
 * Fires on comment status changes.
 *
 * @param string      $new_status The new status.
 * @param string      $old_status The old status.
 * @param \WP_Comment $comment    The comment object.
 */
function fastcgiclear_on_comment_transition($new_status, $old_status, $comment)
{
    if ('approved' === $new_status || 'approved' === $old_status) {
        fastcgiclear_set_cache_stale();
    }
}
add_action('transition_comment_status', 'fastcgiclear_on_comment_transition', 10, 3);

/* -------------------------------------------------------------------------
 * General site changes — options, customizer, menus, themes, plugins
 * ---------------------------------------------------------------------- */

/**
 * Clear cache on critical option updates (e.g. site settings, widgets, theme, plugins).
 *
 * @param string $option The name of the updated option.
 */
function fastcgiclear_on_option_update($option)
{
    $critical_options = [
        'blogname',
        'blogdescription',
        'siteurl',
        'home',
        'sidebars_widgets',
        'permalink_structure',
        'show_on_front',
        'page_on_front',
        'page_for_posts',
    ];

    if (in_array($option, $critical_options, true)) {
        fastcgiclear_set_cache_stale();
    }
}
add_action('updated_option', 'fastcgiclear_on_option_update', 10, 1);

// Navigation menu updates
add_action('wp_update_nav_menu', 'fastcgiclear_set_cache_stale', 10, 0);

// Customizer changes
add_action('customize_save_after', 'fastcgiclear_set_cache_stale', 10, 0);

// Active theme changes
add_action('switch_theme', 'fastcgiclear_set_cache_stale', 10, 0);

// Plugin activation/deactivation changes
add_action('activated_plugin', 'fastcgiclear_set_cache_stale', 10, 0);
add_action('deactivated_plugin', 'fastcgiclear_set_cache_stale', 10, 0);
