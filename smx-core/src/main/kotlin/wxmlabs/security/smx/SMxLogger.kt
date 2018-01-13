package wxmlabs.security.smx

internal var debug = false

internal fun debug(message: String) {
    if (debug) {
        println(message)
    }
}
