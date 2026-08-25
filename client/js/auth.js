/* jshint esversion: 6 */

// Autologin, CSRF protection and token refreshing
$(function () {
    let csrfToken = null;

    function showLoginForm() {
        $('#login__form').removeClass('v-hidden');
    }

    function showAccountInfo(json) {
        $('#account-info').removeClass('v-hidden');
        $('#account-info__id').text(json.user.id);
        $('#account-info__email').text(json.user.email);
        $('#account-info__username').text(json.user.username);
    }

    function loadProfile() {
        return $.ajax({
            url: '/profile',
            method: 'GET',
            dataType: 'json'
        });
    }

    function csrfAjax(options) {
        options = options || {};
        options.headers = options.headers || {};
        options.headers['X-CSRF-Token'] = csrfToken;
        return $.ajax(options);
    }

    function refreshToken() {
        return csrfAjax({
            url: '/profile/refresh',
            method: 'POST',
            dataType: 'json'
        });
    }

    function handleProfileLoadFailure(xhr, errorThrown) {
        const error = xhr.responseJSON || {};
        const errorCode = String(error.code || '').toLowerCase();

        if (!errorCode.includes('expire')) {
            showLoginForm();
            console.error('Could not load profile:', errorThrown);
            return;
        }

        console.log('Trying to refresh token after token has expired...');

        refreshToken()
            .done(function (refreshResponse) {
                if (!refreshResponse.success) {
                    showLoginForm();
                    console.error('Could not refresh token, re-auth needed');
                    return;
                }

                loadProfile()
                    .done(function (json) {
                        showAccountInfo(json);
                    })
                    .fail(function (profileXhr, profileTextStatus, profileError) {
                        showLoginForm();
                        console.error(
                            'Could not load profile after token refresh:',
                            profileXhr.responseJSON || profileError
                        );
                    });
            })
            .fail(function (refreshXhr, refreshTextStatus, refreshError) {
                showLoginForm();
                console.error(
                    'Could not refresh token, re-auth needed:',
                    refreshXhr.responseJSON || refreshError
                );
            });
    }

    // The logout form is a cookie-authenticated POST and therefore needs the CSRF header.
    $('#logout__form').on('submit', function (event) {
        event.preventDefault();

        csrfAjax({
            url: '/signout',
            method: 'POST'
        }).done(function (response) {
            window.location.href = response.logoutEndpoint;
        });
    });

    // Load the CSRF token before making a request that may refresh authentication.
    $.getJSON('/csrf-token')
        .done(function (response) {
            csrfToken = response.csrfToken;

            loadProfile()
                .done(function (json) {
                    showAccountInfo(json);
                })
                .fail(handleProfileLoadFailure);
        })
        .fail(function (xhr, textStatus, errorThrown) {
            showLoginForm();
            console.error('Could not obtain CSRF token:', errorThrown);
        });
});
