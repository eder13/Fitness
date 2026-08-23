// Autologin and refreshing of token
$(function () {
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
            dataType: 'json',
        });
    }

    function refreshToken() {
        return $.ajax({
            url: '/profile/refresh',
            method: 'POST',
            dataType: 'json',
        });
    }

    loadProfile()
        .done(function (json) {
            showAccountInfo(json);
        })
        .fail(function (xhr, textStatus, errorThrown) {
            var error = xhr.responseJSON || {};
            var errorCode = String(error.code || '').toLowerCase();

            if (!errorCode.includes('expire')) {
                showLoginForm();
                console.error('Could not load profile:', errorThrown);
                return;
            }

            console.log('Trying to refresh token after token has expired...');

            refreshToken()
                .done(function (refreshResponse) {
                    if (!refreshResponse.success) {
                        throw new Error(
                            'Could not refresh token, require new auth',
                        );
                    }

                    loadProfile()
                        .done(function (json) {
                            showAccountInfo(json);
                        })
                        .fail(
                            function (
                                profileXhr,
                                profileTextStatus,
                                profileError,
                            ) {
                                showLoginForm();
                                console.error(
                                    'Could not load profile after token refresh:',
                                    profileXhr.responseJSON || profileError,
                                );
                            },
                        );
                })
                .fail(function (refreshXhr, refreshTextStatus, refreshError) {
                    showLoginForm();
                    console.error(
                        'Could not refresh token, require new auth:',
                        refreshXhr.responseJSON || refreshError,
                    );
                });
        });
});
