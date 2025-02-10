import { Dropbox } from 'https://cdn.skypack.dev/dropbox';

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
    return ( (reason) => { throw new Error(message, { cause: reason }); } );
}

export class DropboxCloud {
    /** @type {Object} */
    #dbx;
    /** @type {String} */
    #redirectUri;
    /** @type {String|any|null} */
    #appId;
    /** @type {TokenStorage} */
    #tokenStorage;

    /** @returns {Promise<String?>} */
    async #OAuthRefreshedToken() {
        if (this.#dbx.auth.getRefreshToken()) {
            await this.#dbx.auth.checkAndRefreshAccessToken();
        }
        return this.#dbx.auth.getAccessToken();
    }

    /**
     * @param {WindowProxy} popup
     * @param {String} OAuthState
     * @param {Resolver} OAuthResolve
     * @param {Rejector} OAuthReject
     * @param {MessageEvent} event
     */
    #OAuthRedirectHandler (popup, OAuthState, OAuthResolve, OAuthReject, event) {
        if (Object.hasOwn(event.data, 'OAuthRedirect')) {
            if (popup === event.source) {
                const redirectURL = new URL(event.data.OAuthRedirect);
                const redirect = redirectURL.searchParams;
                const stateObj = JSON.parse(redirect.get('state'));

                if (OAuthState === Object.getOwnPropertyDescriptor(stateObj, 'state')?.value) {
                    OAuthResolve(redirect.get('code'));
                } else {
                    OAuthReject(new Error(`Mismatched state on redirect, something has gone wrong. The search string was "${redirectURL.search}".`));
                }

                event.stopImmediatePropagation();
            }
        }
    };
    /**
     * @param {Number} timeout
     * @param {Rejector} OAuthReject
     */
    #OAuthTimeoutHandler(timeout, OAuthReject) {
        OAuthReject(new Error(`OAuth timed out after ${timeout} seconds.`));
    }
    /**
     * @param {WindowProxy} popup
     * @param {EventListener} redirectHandler
     */
    #OAuthRedirectCleanup(popup, redirectHandler) {
        popup.close();
        window.removeEventListener('message', redirectHandler);
    }
    /**
     * @param {String} OAuthState
     * @param {WindowProxy} popup
     * @param {Number} timeout
     * @return {Promise<String>} OAuthCode
     */
    #OAuthHandleRedirect(OAuthState, popup, timeout) {
        const { promise: OAuthPromise, resolve: OAuthResolve, reject: OAuthReject } = Promise.withResolvers();

        const redirectHandler = this.#OAuthRedirectHandler.bind(this, popup, OAuthState, OAuthResolve, OAuthReject);
        const timeoutHandler  = this.#OAuthTimeoutHandler .bind(this, timeout, OAuthReject);
        const cleanupHandler  = this.#OAuthRedirectCleanup.bind(this, popup, redirectHandler);
        window.addEventListener('message', redirectHandler);
        window.setTimeout(timeoutHandler, timeout * 1000);
        OAuthPromise.finally(cleanupHandler);

        return OAuthPromise;
    }
    /**
     * @param {Number} timeout
     * @return {Promise<String>}
     */
    async #OAuthGetCode(timeout) {
        const state = crypto.randomUUID();
        const authUrl = await this.#dbx.auth.getAuthenticationUrl(this.#redirectUri, JSON.stringify({ state, appId: this.#appId }), 'code', 'offline', null, 'none', true);

        const popup = window.open('about:blank', this.#appId, 'popup=true,width=700,height=960');

        if (!popup) {
            throw new Error('Failed to create popup for authentication!');
        }

        const OAuthPromise = this.#OAuthHandleRedirect(state, popup, timeout);
        popup.location.href = authUrl;
        popup.focus();

        return OAuthPromise;
    }

    /**
     * @param {String} OAuthCode
     * @return {Promise<TokenInfo>}
     */
    async #OAuthGetTokenInfo(OAuthCode) {
        return this.#dbx.auth.getAccessTokenFromCode(this.#redirectUri, OAuthCode)
            .then( (response) => response.result )
        ;
    }

    /**
     * @param {File} file
     * @returns {Promise<undefined>}
     */
    async #uploadSmallFile(file) {
        return this.#dbx.filesUpload({ path: `/${file.name}`, mode: 'overwrite', mute: true, contents: file });
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
    static FILE_SIZE_LIMIT = 150 * 1024 * 1024;
    static OAUTH_TIMEOUT = 120;

    /**
     * @param {String} clientId App key for your Dropbox app
     * @param {String} redirectUri Must call `window.opener.OAuthRedirect(window.location)`, must be included in your Dropbox app's Redirect URIs
     * @param {String?} appId String to identify your app on OAuthRedirect message event
     * @param {TokenStorage?} tokenStorage
     */
    constructor(clientId, redirectUri = '', appId = null, tokenStorage = null) {
        if (!clientId) {
            throw new Error(`You must provide your Client ID (your Dropbox App key)!`);
        }
        this.#dbx = new Dropbox({ clientId: clientId });
        this.#redirectUri = redirectUri;
        this.#appId = appId;
        this.#tokenStorage = tokenStorage;

        this.#dbx.auth.setRefreshToken(tokenStorage?.loadToken());
    }

    /**
     * @param {Number} timeout in seconds
     * @returns {Promise<undefined>}
     */
    async OAuth(timeout = null) {
        if (await this.#OAuthRefreshedToken()) { return; }

        const OAuthCode = await this.#OAuthGetCode(timeout ?? DropboxCloud.OAUTH_TIMEOUT)
            .catch(catchCallback(`Error fetching OAuth code.`))
        ;
        const tokenInfo = await this.#OAuthGetTokenInfo(OAuthCode)
            .catch(catchCallback(`Error converting the OAuth code to an OAuth token.`))
        ;

        this.#dbx.auth.setAccessToken(tokenInfo.access_token);
        this.#dbx.auth.setRefreshToken(tokenInfo.refresh_token);
        this.#dbx.auth.setAccessTokenExpiresAt(Date.now() + tokenInfo.expires_in);
        this.#tokenStorage?.saveToken(tokenInfo.refresh_token);
    }

    /**
     * @param {String} path Starts with `/`
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
