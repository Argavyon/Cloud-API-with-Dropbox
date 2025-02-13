import { Dropbox, DropboxResponseError } from 'https://cdn.skypack.dev/dropbox';

/** @typedef {any} ignore */
/** @typedef {(value: any) => ignore} Resolver */
/** @typedef {(reason: Error|any) => ignore} Rejector */
/** @typedef {(event: Event) => ignore} EventHandler */
/** @typedef {EventHandler|null|{ handleEvent: EventHandler }} EventListener */
/** @typedef {{ [key: String]: any }} APIResult */
/** @typedef {String} Token */
/**
 @typedef {APIResult & {
    access_token: Token,
    refresh_token: Token,
    expires_in: Number
 }} TokenInfo
 */
/** @typedef {{ loadToken: () => Token, saveToken: (token: Token) => ignore }} TokenStorage */

/**
 * @param {String|any} message
 * @returns { (reason: any) => never } Callback that raises an error
 */
const catchCallback = function (message) {
    return ( (reason) => {
        if (reason instanceof DropboxResponseError) {
            throw new Error(
                `${message}\nDropboxResponseError(${reason.error.error}): ${reason.error.error_description}.`,
                { cause: reason }
            );
        } else {
            throw new Error(message, { cause: reason });
        }
    });
}

export class DropboxCloud {
    /** @type {Object} */
    #dbx;
    /** @type {String} */
    #redirectURI;
    /** @type {String|any|null} */
    #appId;
    /** @type {Boolean} */
    #useOfflineToken;
    /** @type {Boolean} */
    #usePopupRedirect;
    /** @type {TokenStorage} */
    #tokenStorage;

    /** @returns {Promise<Boolean>} true if our access token is fresh */
    async #OAuthRefreshToken() {
        if (this.#dbx.auth.getRefreshToken()) {
            return this.#dbx.auth.checkAndRefreshAccessToken()
                .then( (response) => true )
                .catch( (reason) => {
                    if (reason instanceof DropboxResponseError && reason.error.error === 'invalid_grant') {
                        console.debug(new Error(
                            `Error refreshing token: ${reason.error.error_description}. Removing refresh token.`,
                            { cause: reason }
                        ));

                        this.#dbx.auth.setRefreshToken(null);
                        this.#tokenStorage?.saveToken(null);

                        return false;
                    } else {
                        throw reason;
                    }
                })
                .catch(catchCallback('Error refreshing token!'))
            ;
        } else {
            return true;
        }
    }
    /** @returns {Promise<Boolean>} true if our access token is valid (we're logged in) */
    async #OAuthCheckToken() {
        if (await this.#OAuthRefreshToken()) {
            const query = crypto.randomUUID();
            return this.#dbx.checkUser({ query })
                .then(
                    (response) => (response.result.result === query),
                    (reason) => (false)
                )
            ;
        } else {
            return false;
        }
    }

    /**
     * @param {String} OAuthState
     * @param {Resolver} OAuthResolve
     * @param {Rejector} OAuthReject
     * @param {URL} redirectURL
     */
    #OAuthRedirectHandler(OAuthState, OAuthResolve, OAuthReject, redirectURL) {
        const redirect = redirectURL.searchParams;
        const stateObj = JSON.parse(redirect.get('state'));
        const redirectState = Object.getOwnPropertyDescriptor(stateObj, 'state')?.value;

        if (OAuthState === redirectState) {
            OAuthResolve(redirect.get('code'));
        } else {
            OAuthReject(new Error(`Mismatched state on redirect, something has gone wrong. The search string was "${redirectURL.search}".`));
        }
    }

    /**
     * @param {WindowProxy} popup
     * @param {String} OAuthState
     * @param {Resolver} OAuthResolve
     * @param {Rejector} OAuthReject
     * @param {MessageEvent} event
     */
    #popupRedirectHandler(popup, OAuthState, OAuthResolve, OAuthReject, event) {
        if (Object.hasOwn(event.data, 'OAuthRedirect')) {
            if (popup === event.source) {
                const redirectURL = new URL(event.data.OAuthRedirect);
                this.#OAuthRedirectHandler(OAuthState, OAuthResolve, OAuthReject, redirectURL);
                event.stopImmediatePropagation();
            }
        }
    };
    /**
     * @param {Number} timeout
     * @param {Rejector} OAuthReject
     */
    #popupTimeoutHandler(timeout, OAuthReject) {
        OAuthReject(new Error(`OAuth timed out after ${timeout} seconds.`));
    }
    /**
     * @param {WindowProxy} popup
     * @param {EventListener} redirectHandler
     */
    #popupRedirectCleanup(popup, redirectHandler) {
        popup.close();
        window.removeEventListener('message', redirectHandler);
    }
    /**
     * @param {String} OAuthState
     * @param {WindowProxy} popup
     * @param {Number} timeout
     * @return {Promise<String>} OAuthCode
     */
    #handlePopupRedirect(OAuthState, popup, timeout) {
        const { promise: OAuthPromise, resolve: OAuthResolve, reject: OAuthReject } = Promise.withResolvers();

        const redirectHandler = this.#popupRedirectHandler.bind(this, popup, OAuthState, OAuthResolve, OAuthReject);
        const timeoutHandler  = this.#popupTimeoutHandler .bind(this, timeout, OAuthReject);
        const cleanupHandler  = this.#popupRedirectCleanup.bind(this, popup, redirectHandler);
        window.addEventListener('message', redirectHandler);
        window.setTimeout(timeoutHandler, timeout * 1000);
        OAuthPromise.finally(cleanupHandler);

        return OAuthPromise;
    }
    /**
     *
     * @param {String} OAuthState
     * @param {String} OAuthURL
     * @param {Number} timeout
     * @returns {Promise<String>} OAuthCode
     */
    async #OAuthPopupRedirect(OAuthState, OAuthURL, timeout) {
        const popup = window.open('about:blank', this.#appId, 'popup=true,width=700,height=960');

        if (!popup) {
            throw new Error('Failed to create popup for authentication!');
        }

        const OAuthPromise = this.#handlePopupRedirect(OAuthState, popup, timeout);
        popup.location.href = OAuthURL;
        popup.focus();

        return OAuthPromise;
    }

    /**
     * @param {URL} redirectURL
     * @returns {Promise<String>} OAuthCode
     */
    #navigationRedirectHandler(redirectURL) {
        const OAuthState = sessionStorage.getItem(`OAuthState-${this.#appId}`);
        const CodeVerifier = sessionStorage.getItem(`CodeVerifier-${this.#appId}`);
        this.#dbx.auth.setCodeVerifier(CodeVerifier);
        const { promise: OAuthPromise, resolve: OAuthResolve, reject: OAuthReject } = Promise.withResolvers();
        this.#OAuthRedirectHandler(OAuthState, OAuthResolve, OAuthReject, redirectURL);
        return OAuthPromise;
    }
    /**
     * @param {String} OAuthState
     * @param {String} OAuthURL
     * @return {null}
     */
    #OAuthNavigationRedirect(OAuthState, OAuthURL) {
        sessionStorage.setItem(`OAuthState-${this.#appId}`, OAuthState);
        sessionStorage.setItem(`CodeVerifier-${this.#appId}`, this.#dbx.auth.getCodeVerifier());
        window.location.replace(OAuthURL);
        return null;
    }

    /**
     * @param {Number} timeout
     * @return {Promise<String>?} OAuthCode, unless we same-page navigate to Dropbox
     */
    async #OAuthGetCode(timeout, offlineToken, popupRedirect) {
        const currentURL = new URL(window.location);
        const redirect = currentURL.searchParams;

        if (redirect.has('code') && redirect.has('state')) {
            return this.#navigationRedirectHandler(currentURL);
        } else {
            const state = crypto.randomUUID();
            const authType = 'code';
            const tokenType = offlineToken ? 'offline' : 'online';
            const scope = null;
            const includeGrantedScopes = 'none';
            const usePKCE = true;

            const OAuthURL = await this.#dbx.auth.getAuthenticationUrl(
                this.#redirectURI,
                JSON.stringify({ state, appId: this.#appId }),
                authType,
                tokenType,
                scope,
                includeGrantedScopes,
                usePKCE
            );

            if (popupRedirect) {
                return this.#OAuthPopupRedirect(state, OAuthURL, timeout);
            } else {
                return this.#OAuthNavigationRedirect(state, OAuthURL);
            }
        }
    }

    /**
     * @param {String} OAuthCode
     * @return {Promise<TokenInfo>}
     */
    async #OAuthGetTokenInfo(OAuthCode) {
        return this.#dbx.auth.getAccessTokenFromCode(this.#redirectURI, OAuthCode)
            .then( (response) => response.result )
        ;
    }

    /**
     * @param {File} file
     * @param {String?} dir Starts with `/`
     * @returns {Promise<undefined>}
     */
    async #uploadSmallFile(file, dir = '/') {
        if (dir.at(-1) != '/') {
            dir += '/';
        }
        return this.#dbx.filesUpload({ path: `${dir}${file.name}`, mode: 'overwrite', mute: true, contents: file });
    }
    /**
     * @param {File} file
     * @returns {Promise<undefined>}
     */
    async #uploadLargeFile(file) {
        const fileChunks = Array.from({ length: Math.ceil(file.size / DropboxCloud.CHUNK_SIZE) })
            .map( (_, chunkIdx) => file.slice(chunkIdx * DropboxCloud.CHUNK_SIZE, (chunkIdx + 1) * DropboxCloud.CHUNK_SIZE) )
        ;

        const uploadSession = await this.#dbx.filesUploadSessionStart({ close: false }).then( (response) => response.result.session_id );

        for (const chunkIdx in fileChunks) {
            const cursor = { session_id: uploadSession, offset: chunkIdx * DropboxCloud.CHUNK_SIZE };
            await this.#dbx.filesUploadSessionAppendV2({ cursor: cursor, close: false, contents: fileChunks[chunkIdx] });
        }

        const cursor = { session_id: uploadSession, offset: file.size };
        const commit = { path: `/${file.name}`, mode: 'overwrite', mute: true };
        return this.#dbx.filesUploadSessionFinish({ cursor: cursor, commit: commit });
    }

    ////////////////////////////
    // PUBLIC API STARTS HERE //
    ////////////////////////////

    /** @const CHUNK_SIZE 8MB - Dropbox JavaScript API suggested chunk size */
    static CHUNK_SIZE = 12 * 1024 * 1024;
    /** @property Small file size limit */
    static FILE_SIZE_LIMIT = 150 * 1024 * 1024;
    /** @property Default timeout in seconds */
    static OAUTH_TIMEOUT = 120;

    /**
     * @param {String} clientId App key for your Dropbox app.
     * @param {String} redirectURI Must be included in your Dropbox app's Redirect URIs, must call `window.opener.OAuthRedirect(window.location)` if `popupRedirect` is `true`.
     * @param {String?} appId Optional. String to identify your app on OAuthRedirect message event.
     * @param {TokenStorage?} tokenStorage Optional. An object with `loadToken` and `saveToken` methods that persist the refresh token. Only applies when `offlineToken` is `true`.
     * @param {Boolean} offlineToken Optional. Sets default access token type for OAuth: offline or online. All access tokens expire in a few hours, but offline access tokens can have their duration refreshed.
     * @param {Boolean} popupRedirect Optional. Sets default redirect type: popup or same-page-navigation.
     */
    constructor(clientId, redirectURI = ' ', appId = null, tokenStorage = null, offlineToken = true, popupRedirect = true) {
        if (!clientId) {
            throw new Error(`You must provide your Client ID (your Dropbox App key)!`);
        }
        this.#dbx = new Dropbox({ clientId: clientId });
        this.#redirectURI = redirectURI;
        this.#appId = appId;
        this.#useOfflineToken = offlineToken;
        this.#usePopupRedirect = popupRedirect;
        this.#tokenStorage = tokenStorage;

        this.#dbx.auth.setRefreshToken(tokenStorage?.loadToken());
    }

    /**
     * @param {Number?} timeout in seconds, defaults to DropboxCloud.OAUTH_TIMEOUT
     * @param {Boolean?} offlineToken Override default access token type
     * @param {Boolean?} popupRedirect Override default redirect type
     * @returns {Promise<undefined>}
     */
    async OAuth(timeout = null, offlineToken = null, popupRedirect = null) {
        if (await this.#OAuthCheckToken()) { return; }

        timeout ??= DropboxCloud.OAUTH_TIMEOUT;
        offlineToken ??= this.#useOfflineToken;
        popupRedirect ??= this.#usePopupRedirect;

        const OAuthCode = await this.#OAuthGetCode(timeout, offlineToken, popupRedirect)
            .catch(catchCallback(`Error fetching OAuth Code.`))
        ;
        if (!OAuthCode && !popupRedirect) {
            // Navigating for authentication
        } else {
            const tokenInfo = await this.#OAuthGetTokenInfo(OAuthCode)
                .catch(catchCallback(`Error converting the OAuth Code to an OAuth Token.`))
            ;

            this.#dbx.auth.setAccessToken(tokenInfo.access_token);
            if (offlineToken) {
                this.#dbx.auth.setRefreshToken(tokenInfo.refresh_token);
                this.#dbx.auth.setAccessTokenExpiresAt(Date.now() + tokenInfo.expires_in);
                this.#tokenStorage?.saveToken(tokenInfo.refresh_token);
            }
        }
    }

    /**
     * @param {String} path Starts with `/`
     * @param {Number?} timeout for OAuth, in seconds
     * @return {Promise<APIResult>}
     */
    async fetchFileList(path, timeout = null) {
        await this.OAuth(timeout);
        return this.#dbx.filesListFolder({ path: path })
            .then( (response) => response.result )
            .catch(catchCallback(`Error fetching file list from ${path}.`))
        ;
    }

    /**
     * @param {String} path Starts with `/`
     * @param {Number?} timeout for OAuth, in seconds
     * @return {Promise<APIResult>}
     */
    async downloadFile(path, timeout = null) {
        await this.OAuth(timeout);
        return this.#dbx.filesDownload({ path: path })
            .then( (response) => response.result )
            .catch(catchCallback(`Error downloading file from ${path}.`))
        ;
    }

    /**
     * @param {File} file
     * @param {Number?} timeout for OAuth, in seconds
     * @return {Promise<APIResult>}
     */
    async uploadFile(file, timeout = null) {
        await this.OAuth(timeout);
        return (file.size < DropboxCloud.FILE_SIZE_LIMIT ? this.#uploadSmallFile(file) : this.#uploadLargeFile(file))
            .then( (response) => response.result )
            .catch(catchCallback(`Error uploading file ${file}.`))
        ;
    }
}
