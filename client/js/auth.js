/* jshint esversion: 6 */

// CSRF protection and token refreshing
$(function () {
    let csrfToken = null;

    function showLoginForm() {
        $('#login__form').removeClass('v-hidden');
    }

    window.showLoginError = function (message) {
        const error = $('#login__form-error');
        error.text(message || 'Die Anmeldung ist derzeit nicht möglich. Bitte versuchen Sie es später erneut.');
        error.removeClass('v-hidden');
    };

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
            return;
        }

        console.log('Trying to refresh token after token has expired...');

        refreshToken()
            .done(function (refreshResponse) {
                if (!refreshResponse.success) {
                    showLoginForm();
                    showLoginError('Ihre Anmeldung ist abgelaufen. Bitte melden Sie sich erneut an.');
                    return;
                }

                loadProfile()
                    .done(function (json) {
                        showAccountInfo(json);
                    })
                    .fail(function (profileXhr, profileTextStatus, profileError) {
                        showLoginForm();
                        showLoginError('Die Anmeldung konnte nicht erneuert werden. Bitte melden Sie sich erneut an.');
                    });
            })
            .fail(function (refreshXhr, refreshTextStatus, refreshError) {
                showLoginForm();
                showLoginError('Die Anmeldung konnte nicht erneuert werden. Bitte melden Sie sich erneut an.');
            });
    }

    $('#logout__form').on('submit', function (event) {
        event.preventDefault();

        csrfAjax({
            url: '/signout',
            method: 'POST'
        }).done(function (response) {
            window.location.href = response.logoutEndpoint;
        });
    });

    $('#logout__form-logged-in').on('submit', function (event) {
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
            showLoginError('Der Login-Dienst ist derzeit nicht erreichbar. Bitte versuchen Sie es später erneut.');
        });

    if (typeof SOCKET !== 'undefined') {
        SOCKET.on('connect_error', function () {
            showLoginForm();
            showLoginError('Die Anmeldung konnte nicht geprüft werden. Bitte melden Sie sich erneut an.');
        });
    }
});
