package eu.kanade.tachiyomi.animeextension.en.hanime

import java.security.MessageDigest

/**
 * Signature provider that computes the hanime.tv CDN signature natively via
 * direct SHA-256 hashing, replacing WASM execution and WebView extraction.
 *
 * ## Algorithm (app2 — for universal-cdn.com CDN endpoints)
 *
 * The CDN API signature is computed as:
 * ```
 * SHA256("994482" + "2${t}8${t}" + "113")
 * ```
 *
 * Where `t` = `System.currentTimeMillis() / 1000L` (Unix seconds).
 *
 * The resulting 32-byte hash is formatted as a 64-character lowercase
 * hexadecimal string and sent as the `x-signature` header alongside
 * the timestamp in the `x-claim` header with `x-signature-version: app2`.
 *
 * ## Why this exists
 *
 * The extension targets `www.universal-cdn.com` CDN which requires the `app2`
 * signature format. The old `web2` format (`SHA256("{t},Xkdi29,...")`) is only
 * accepted by `hanime.tv` web endpoints and is rejected by the CDN with 403.
 *
 * ## Thread safety
 *
 * This provider is thread-safe. [MessageDigest] is created fresh per
 * [getSignature] call, so no mutable shared state exists.
 */
open class NativeSignatureProvider : SignatureProvider {

    companion object {
        /** Static prefix for the app2 signature algorithm. */
        private const val PREFIX = "994482"

        /** Static suffix for the app2 signature algorithm. */
        private const val SUFFIX = "113"
    }

    override val name: String = "native"

    /**
     * Timestamp source — returns current Unix time in seconds.
     * Overridable in tests to pin a fixed timestamp for known-answer verification.
     */
    protected open val timestampProvider: () -> Long = { System.currentTimeMillis() / 1000L }

    /**
     * Compute a fresh app2 signature by hashing the current timestamp.
     *
     * The input format is: `{PREFIX}2{t}8{t}{SUFFIX}`
     * The hash is SHA-256, formatted as 64 lowercase hex characters.
     */
    override suspend fun getSignature(): Signature {
        val t = timestampProvider()
        val input = "${PREFIX}2${t}8${t}${SUFFIX}"
        val digest = MessageDigest.getInstance("SHA-256")
        val hashBytes = digest.digest(input.toByteArray(Charsets.UTF_8))
        val hex = hashBytes.joinToString("") { "%02x".format(it) }
        return Signature(signature = hex, time = t.toString())
    }

    /** No resources to release — this is a no-op. */
    override fun close() {}
}
