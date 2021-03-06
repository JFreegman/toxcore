%{
/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2013 Tox project.
 */

/*
 * The Tox public API.
 */
#ifndef C_TOXCORE_TOXCORE_TOX_H
#define C_TOXCORE_TOXCORE_TOX_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

//!TOKSTYLE-

#ifdef __cplusplus
extern "C" {
#endif
%}


/*****************************************************************************
 * `tox.h` SHOULD *NOT* BE EDITED MANUALLY – any changes should be made to   *
 * `tox.api.h`, located in `toxcore/`. For instructions on how to            *
 * generate `tox.h` from `tox.api.h` please refer to `docs/apidsl.md`        *
 *****************************************************************************/


/**
 * @page core Public core API for Tox clients.
 *
 * Every function that can fail takes a function-specific error code pointer
 * that can be used to diagnose problems with the Tox state or the function
 * arguments. The error code pointer can be NULL, which does not influence the
 * function's behaviour, but can be done if the reason for failure is irrelevant
 * to the client.
 *
 * The exception to this rule are simple allocation functions whose only failure
 * mode is allocation failure. They return NULL in that case, and do not set an
 * error code.
 *
 * Every error code type has an OK value to which functions will set their error
 * code value on success. Clients can keep their error code uninitialised before
 * passing it to a function. The library guarantees that after returning, the
 * value pointed to by the error code pointer has been initialised.
 *
 * Functions with pointer parameters often have a NULL error code, meaning they
 * could not perform any operation, because one of the required parameters was
 * NULL. Some functions operate correctly or are defined as effectless on NULL.
 *
 * Some functions additionally return a value outside their
 * return type domain, or a bool containing true on success and false on
 * failure.
 *
 * All functions that take a Tox instance pointer will cause undefined behaviour
 * when passed a NULL Tox pointer.
 *
 * All integer values are expected in host byte order.
 *
 * Functions with parameters with enum types cause unspecified behaviour if the
 * enumeration value is outside the valid range of the type. If possible, the
 * function will try to use a sane default, but there will be no error code,
 * and one possible action for the function to take is to have no effect.
 *
 * Integer constants and the memory layout of publicly exposed structs are not
 * part of the ABI.
 */

/**
 * @subsection events Events and callbacks
 *
 * Events are handled by callbacks. One callback can be registered per event.
 * All events have a callback function type named `tox_{event}_cb` and a
 * function to register it named `tox_callback_{event}`. Passing a NULL
 * callback will result in no callback being registered for that event. Only
 * one callback per event can be registered, so if a client needs multiple
 * event listeners, it needs to implement the dispatch functionality itself.
 *
 * The last argument to a callback is the user data pointer. It is passed from
 * ${tox.iterate} to each callback in sequence.
 *
 * The user data pointer is never stored or dereferenced by any library code, so
 * can be any pointer, including NULL. Callbacks must all operate on the same
 * object type. In the apidsl code (tox.in.h), this is denoted with `any`. The
 * `any` in ${tox.iterate} must be the same `any` as in all callbacks. In C,
 * lacking parametric polymorphism, this is a pointer to void.
 *
 * Old style callbacks that are registered together with a user data pointer
 * receive that pointer as argument when they are called. They can each have
 * their own user data pointer of their own type.
 */

/**
 * @subsection threading Threading implications
 *
 * It is possible to run multiple concurrent threads with a Tox instance for
 * each thread. It is also possible to run all Tox instances in the same thread.
 * A common way to run Tox (multiple or single instance) is to have one thread
 * running a simple ${tox.iterate} loop, sleeping for ${tox.iteration_interval}
 * milliseconds on each iteration.
 *
 * If you want to access a single Tox instance from multiple threads, access
 * to the instance must be synchronised. While multiple threads can concurrently
 * access multiple different Tox instances, no more than one API function can
 * operate on a single instance at any given time.
 *
 * Functions that write to variable length byte arrays will always have a size
 * function associated with them. The result of this size function is only valid
 * until another mutating function (one that takes a pointer to non-const Tox)
 * is called. Thus, clients must ensure that no other thread calls a mutating
 * function between the call to the size function and the call to the retrieval
 * function.
 *
 * E.g. to get the current nickname, one would write
 *
 * @code
 * size_t length = ${tox.self.name.size}(tox);
 * uint8_t *name = malloc(length);
 * if (!name) abort();
 * ${tox.self.name.get}(tox, name);
 * @endcode
 *
 * If any other thread calls ${tox.self.name.set} while this thread is allocating
 * memory, the length may have become invalid, and the call to
 * ${tox.self.name.get} may cause undefined behaviour.
 */

// The rest of this file is in class tox.
class tox {

/**
 * The Tox instance type. All the state associated with a connection is held
 * within the instance. Multiple instances can exist and operate concurrently.
 * The maximum number of Tox instances that can exist on a single network
 * device is limited. Note that this is not just a per-process limit, since the
 * limiting factor is the number of usable ports on a device.
 */
struct this;


/*******************************************************************************
 *
 * :: API version
 *
 ******************************************************************************/


/**
 * The major version number. Incremented when the API or ABI changes in an
 * incompatible way.
 *
 * The function variants of these constants return the version number of the
 * library. They can be used to display the Tox library version or to check
 * whether the client is compatible with the dynamically linked version of Tox.
 */
const VERSION_MAJOR                = 0;

/**
 * The minor version number. Incremented when functionality is added without
 * breaking the API or ABI. Set to 0 when the major version number is
 * incremented.
 */
const VERSION_MINOR                = 2;

/**
 * The patch or revision number. Incremented when bugfixes are applied without
 * changing any functionality or API or ABI.
 */
const VERSION_PATCH                = 12;

/**
 * A macro to check at preprocessing time whether the client code is compatible
 * with the installed version of Tox. Leading zeros in the version number are
 * ignored. E.g. 0.1.5 is to 0.1.4 what 1.5 is to 1.4, that is: it can add new
 * features, but can't break the API.
 */
#define TOX_VERSION_IS_API_COMPATIBLE(MAJOR, MINOR, PATCH)              \
  ((TOX_VERSION_MAJOR > 0 && TOX_VERSION_MAJOR == MAJOR) && (           \
    /* 1.x.x, 2.x.x, etc. with matching major version. */               \
    TOX_VERSION_MINOR > MINOR ||                                        \
    (TOX_VERSION_MINOR == MINOR && TOX_VERSION_PATCH >= PATCH)          \
  )) || ((TOX_VERSION_MAJOR == 0 && MAJOR == 0) && (                    \
    /* 0.x.x makes minor behave like major above. */                    \
    ((TOX_VERSION_MINOR > 0 && TOX_VERSION_MINOR == MINOR) && (         \
      TOX_VERSION_PATCH >= PATCH                                        \
    )) || ((TOX_VERSION_MINOR == 0 && MINOR == 0) && (                  \
      /* 0.0.x and 0.0.y are only compatible if x == y. */              \
      TOX_VERSION_PATCH == PATCH                                        \
    ))                                                                  \
  ))

static namespace version {

  /**
   * Return whether the compiled library version is compatible with the passed
   * version numbers.
   */
  bool is_compatible(uint32_t major, uint32_t minor, uint32_t patch);

}

/**
 * A convenience macro to call tox_version_is_compatible with the currently
 * compiling API version.
 */
#define TOX_VERSION_IS_ABI_COMPATIBLE()                         \
  tox_version_is_compatible(TOX_VERSION_MAJOR, TOX_VERSION_MINOR, TOX_VERSION_PATCH)

/*******************************************************************************
 *
 * :: Numeric constants
 *
 * The values of these are not part of the ABI. Prefer to use the function
 * versions of them for code that should remain compatible with future versions
 * of toxcore.
 *
 ******************************************************************************/


/**
 * The size of a Tox Public Key in bytes.
 */
const PUBLIC_KEY_SIZE              = 32;

/**
 * The size of a Tox Secret Key in bytes.
 */
const SECRET_KEY_SIZE              = 32;

/**
 * The size of a Tox Conference unique id in bytes.
 *
 * @deprecated Use $CONFERENCE_ID_SIZE instead.
 */
const CONFERENCE_UID_SIZE          = 32;

/**
 * The size of a Tox Conference unique id in bytes.
 */
const CONFERENCE_ID_SIZE           = 32;

/**
 * The size of the nospam in bytes when written in a Tox address.
 */
const NOSPAM_SIZE                  = sizeof(uint32_t);

/**
 * The size of a Tox address in bytes. Tox addresses are in the format
 * [Public Key ($PUBLIC_KEY_SIZE bytes)][nospam (4 bytes)][checksum (2 bytes)].
 *
 * The checksum is computed over the Public Key and the nospam value. The first
 * byte is an XOR of all the even bytes (0, 2, 4, ...), the second byte is an
 * XOR of all the odd bytes (1, 3, 5, ...) of the Public Key and nospam.
 */
const ADDRESS_SIZE                = PUBLIC_KEY_SIZE + NOSPAM_SIZE + sizeof(uint16_t);

/**
 * Maximum length of a nickname in bytes.
 *
 * @deprecated The macro will be removed in 0.3.0. Use the function instead.
 */
const MAX_NAME_LENGTH             = 128;

/**
 * Maximum length of a status message in bytes.
 *
 * @deprecated The macro will be removed in 0.3.0. Use the function instead.
 */
const MAX_STATUS_MESSAGE_LENGTH   = 1007;

/**
 * Maximum length of a friend request message in bytes.
 *
 * @deprecated The macro will be removed in 0.3.0. Use the function instead.
 */
const MAX_FRIEND_REQUEST_LENGTH   = 1016;

/**
 * Maximum length of a single message after which it should be split.
 *
 * @deprecated The macro will be removed in 0.3.0. Use the function instead.
 */
const MAX_MESSAGE_LENGTH          = 1372;

/**
 * Maximum size of custom packets. TODO(iphydf): should be LENGTH?
 *
 * @deprecated The macro will be removed in 0.3.0. Use the function instead.
 */
const MAX_CUSTOM_PACKET_SIZE      = 1373;

/**
 * The number of bytes in a hash generated by $hash.
 */
const HASH_LENGTH                 = 32;

/**
 * The number of bytes in a file id.
 */
const FILE_ID_LENGTH              = 32;

/**
 * Maximum file name length for file transfers.
 *
 * @deprecated The macro will be removed in 0.3.0. Use the function instead.
 */
const MAX_FILENAME_LENGTH         = 255;

/**
 * Maximum length of a hostname, e.g. proxy or bootstrap node names.
 *
 * This length does not include the NUL byte. Hostnames are NUL-terminated C
 * strings, so they are 255 characters plus one NUL byte.
 *
 * @deprecated The macro will be removed in 0.3.0. Use the function instead.
 */
const MAX_HOSTNAME_LENGTH         = 255;


/*******************************************************************************
 *
 * :: Global enumerations
 *
 ******************************************************************************/


/**
 * Represents the possible statuses a client can have.
 *
 * @deprecated All UPPER_CASE enum type names are deprecated. Use the
 *   Camel_Snake_Case versions, instead.
 */
enum class USER_STATUS {
  /**
   * User is online and available.
   */
  NONE,
  /**
   * User is away. Clients can set this e.g. after a user defined
   * inactivity time.
   */
  AWAY,
  /**
   * User is busy. Signals to other clients that this client does not
   * currently wish to communicate.
   */
  BUSY,
}


/**
 * Represents message types for ${tox.friend.send.message} and conference
 * messages.
 *
 * @deprecated All UPPER_CASE enum type names are deprecated. Use the
 *   Camel_Snake_Case versions, instead.
 */
enum class MESSAGE_TYPE {
  /**
   * Normal text message. Similar to PRIVMSG on IRC.
   */
  NORMAL,
  /**
   * A message describing an user action. This is similar to /me (CTCP ACTION)
   * on IRC.
   */
  ACTION,
}


/*******************************************************************************
 *
 * :: Startup options
 *
 ******************************************************************************/


/**
 * Type of proxy used to connect to TCP relays.
 *
 * @deprecated All UPPER_CASE enum type names are deprecated. Use the
 *   Camel_Snake_Case versions, instead.
 */
enum class PROXY_TYPE {
  /**
   * Don't use a proxy.
   */
  NONE,
  /**
   * HTTP proxy using CONNECT.
   */
  HTTP,
  /**
   * SOCKS proxy for simple socket pipes.
   */
  SOCKS5,
}

/**
 * Type of savedata to create the Tox instance from.
 *
 * @deprecated All UPPER_CASE enum type names are deprecated. Use the
 *   Camel_Snake_Case versions, instead.
 */
enum class SAVEDATA_TYPE {
  /**
   * No savedata.
   */
  NONE,
  /**
   * Savedata is one that was obtained from ${savedata.get}.
   */
  TOX_SAVE,
  /**
   * Savedata is a secret key of length $SECRET_KEY_SIZE.
   */
  SECRET_KEY,
}


/**
 * Severity level of log messages.
 *
 * @deprecated All UPPER_CASE enum type names are deprecated. Use the
 *   Camel_Snake_Case versions, instead.
 */
enum class LOG_LEVEL {
  /**
   * Very detailed traces including all network activity.
   */
  TRACE,
  /**
   * Debug messages such as which port we bind to.
   */
  DEBUG,
  /**
   * Informational log messages such as video call status changes.
   */
  INFO,
  /**
   * Warnings about internal inconsistency or logic errors.
   */
  WARNING,
  /**
   * Severe unexpected errors caused by external or internal inconsistency.
   */
  ERROR,
}

/**
 * This event is triggered when the toxcore library logs an internal message.
 * This is mostly useful for debugging. This callback can be called from any
 * function, not just $iterate. This means the user data lifetime must at
 * least extend between registering and unregistering it or $kill.
 *
 * Other toxcore modules such as toxav may concurrently call this callback at
 * any time. Thus, user code must make sure it is equipped to handle concurrent
 * execution, e.g. by employing appropriate mutex locking.
 *
 * @param level The severity of the log message.
 * @param file The source file from which the message originated.
 * @param line The source line from which the message originated.
 * @param func The function from which the message originated.
 * @param message The log message.
 * @param user_data The user data pointer passed to $new in options.
 */
typedef void log_cb(LOG_LEVEL level, string file, uint32_t line, string func, string message, any user_data);


static class options {
  /**
   * This struct contains all the startup options for Tox. You must $new to
   * allocate an object of this type.
   *
   * WARNING: Although this struct happens to be visible in the API, it is
   * effectively private. Do not allocate this yourself or access members
   * directly, as it *will* break binary compatibility frequently.
   *
   * @deprecated The memory layout of this struct (size, alignment, and field
   * order) is not part of the ABI. To remain compatible, prefer to use $new to
   * allocate the object and accessor functions to set the members. The struct
   * will become opaque (i.e. the definition will become private) in v0.3.0.
   */
  struct this [get, set] {
    /**
     * The type of socket to create.
     *
     * If this is set to false, an IPv4 socket is created, which subsequently
     * only allows IPv4 communication.
     * If it is set to true, an IPv6 socket is created, allowing both IPv4 and
     * IPv6 communication.
     */
    bool ipv6_enabled;

    /**
     * Enable the use of UDP communication when available.
     *
     * Setting this to false will force Tox to use TCP only. Communications will
     * need to be relayed through a TCP relay node, potentially slowing them down.
     *
     * If a proxy is enabled, UDP will be disabled if either toxcore or the
     * proxy don't support proxying UDP messages.
     */
    bool udp_enabled;

    /**
     * Enable local network peer discovery.
     *
     * Disabling this will cause Tox to not look for peers on the local network.
     */
    bool local_discovery_enabled;

    namespace proxy {
      /**
       * Pass communications through a proxy.
       */
      PROXY_TYPE type;

      /**
       * The IP address or DNS name of the proxy to be used.
       *
       * If used, this must be non-NULL and be a valid DNS name. The name must not
       * exceed $MAX_HOSTNAME_LENGTH characters, and be in a NUL-terminated C string
       * format ($MAX_HOSTNAME_LENGTH includes the NUL byte).
       *
       * This member is ignored (it can be NULL) if proxy_type is ${PROXY_TYPE.NONE}.
       *
       * The data pointed at by this member is owned by the user, so must
       * outlive the options object.
       */
      string host;

      /**
       * The port to use to connect to the proxy server.
       *
       * Ports must be in the range (1, 65535). The value is ignored if
       * proxy_type is ${PROXY_TYPE.NONE}.
       */
      uint16_t port;
    }

    /**
     * The start port of the inclusive port range to attempt to use.
     *
     * If both start_port and end_port are 0, the default port range will be
     * used: [33445, 33545].
     *
     * If either start_port or end_port is 0 while the other is non-zero, the
     * non-zero port will be the only port in the range.
     *
     * Having start_port > end_port will yield the same behavior as if start_port
     * and end_port were swapped.
     */
    uint16_t start_port;

    /**
     * The end port of the inclusive port range to attempt to use.
     */
    uint16_t end_port;

    /**
     * The port to use for the TCP server (relay). If 0, the TCP server is
     * disabled.
     *
     * Enabling it is not required for Tox to function properly.
     *
     * When enabled, your Tox instance can act as a TCP relay for other Tox
     * instance. This leads to increased traffic, thus when writing a client
     * it is recommended to enable TCP server only if the user has an option
     * to disable it.
     */
    uint16_t tcp_port;

    /**
     * Enables or disables UDP hole-punching in toxcore. (Default: enabled).
     */
    bool hole_punching_enabled;

    namespace savedata {
      /**
       * The type of savedata to load from.
       */
      SAVEDATA_TYPE type;

      /**
       * The savedata.
       *
       * The data pointed at by this member is owned by the user, so must
       * outlive the options object.
       */
      const uint8_t[length] data;

      /**
       * The length of the savedata.
       */
      size_t length;
    }

    namespace log {
      /**
       * Logging callback for the new tox instance.
       */
      log_cb *callback;

      /**
       * User data pointer passed to the logging callback.
       */
      any user_data;
    }

    /**
     * These options are experimental, so avoid writing code that depends on
     * them. Options marked "experimental" may change their behaviour or go away
     * entirely in the future, or may be renamed to something non-experimental
     * if they become part of the supported API.
     */
    namespace experimental {
      /**
       * Make public API functions thread-safe using a per-instance lock.
       *
       * Default: false.
       */
      bool thread_safety;
    }
  }


  /**
   * Initialises a $this object with the default options.
   *
   * The result of this function is independent of the original options. All
   * values will be overwritten, no values will be read (so it is permissible
   * to pass an uninitialised object).
   *
   * If options is NULL, this function has no effect.
   *
   * @param options An options object to be filled with default options.
   */
  void default();


  /**
   * Allocates a new $this object and initialises it with the default
   * options. This function can be used to preserve long term ABI compatibility by
   * giving the responsibility of allocation and deallocation to the Tox library.
   *
   * Objects returned from this function must be freed using the $free
   * function.
   *
   * @return A new $this object with default options or NULL on failure.
   */
  static this new() {
    /**
     * The function failed to allocate enough memory for the options struct.
     */
    MALLOC,
  }


  /**
   * Releases all resources associated with an options objects.
   *
   * Passing a pointer that was not returned by $new results in
   * undefined behaviour.
   */
  void free();
}


/*******************************************************************************
 *
 * :: Creation and destruction
 *
 ******************************************************************************/


/**
 * @brief Creates and initialises a new Tox instance with the options passed.
 *
 * This function will bring the instance into a valid state. Running the event
 * loop with a new instance will operate correctly.
 *
 * If loading failed or succeeded only partially, the new or partially loaded
 * instance is returned and an error code is set.
 *
 * @param options An options object as described above. If this parameter is
 *   NULL, the default options are used.
 *
 * @see $iterate for the event loop.
 *
 * @return A new Tox instance pointer on success or NULL on failure.
 */
static this new(const options_t *options) {
  NULL,
  /**
   * The function was unable to allocate enough memory to store the internal
   * structures for the Tox object.
   */
  MALLOC,
  /**
   * The function was unable to bind to a port. This may mean that all ports
   * have already been bound, e.g. by other Tox instances, or it may mean
   * a permission error. You may be able to gather more information from errno.
   */
  PORT_ALLOC,

  namespace PROXY {
    /**
     * proxy_type was invalid.
     */
    BAD_TYPE,
    /**
     * proxy_type was valid but the proxy_host passed had an invalid format
     * or was NULL.
     */
    BAD_HOST,
    /**
     * proxy_type was valid, but the proxy_port was invalid.
     */
    BAD_PORT,
    /**
     * The proxy address passed could not be resolved.
     */
    NOT_FOUND,
  }

  namespace LOAD {
    /**
     * The byte array to be loaded contained an encrypted save.
     */
    ENCRYPTED,
    /**
     * The data format was invalid. This can happen when loading data that was
     * saved by an older version of Tox, or when the data has been corrupted.
     * When loading from badly formatted data, some data may have been loaded,
     * and the rest is discarded. Passing an invalid length parameter also
     * causes this error.
     */
    BAD_FORMAT,
  }
}


/**
 * Releases all resources associated with the Tox instance and disconnects from
 * the network.
 *
 * After calling this function, the Tox pointer becomes invalid. No other
 * functions can be called, and the pointer value can no longer be read.
 */
void kill();


uint8_t[size] savedata {
  /**
   * Calculates the number of bytes required to store the tox instance with
   * $get. This function cannot fail. The result is always greater than 0.
   *
   * @see threading for concurrency implications.
   */
  size();

  /**
   * Store all information associated with the tox instance to a byte array.
   *
   * @param savedata A memory region large enough to store the tox instance
   *   data. Call $size to find the number of bytes required. If this parameter
   *   is NULL, this function has no effect.
   */
  get();
}


/*******************************************************************************
 *
 * :: Connection lifecycle and event loop
 *
 ******************************************************************************/


/**
 * Sends a "get nodes" request to the given bootstrap node with IP, port, and
 * public key to setup connections.
 *
 * This function will attempt to connect to the node using UDP. You must use
 * this function even if ${options.this.udp_enabled} was set to false.
 *
 * @param host The hostname or IP address (IPv4 or IPv6) of the node. Must be
 *   at most $MAX_HOSTNAME_LENGTH chars, including the NUL byte.
 * @param port The port on the host on which the bootstrap Tox instance is
 *   listening.
 * @param public_key The long term public key of the bootstrap node
 *   ($PUBLIC_KEY_SIZE bytes).
 * @return true on success.
 */
bool bootstrap(string host, uint16_t port, const uint8_t[PUBLIC_KEY_SIZE] public_key) {
  NULL,
  /**
   * The hostname could not be resolved to an IP address, or the IP address
   * passed was invalid.
   */
  BAD_HOST,
  /**
   * The port passed was invalid. The valid port range is (1, 65535).
   */
  BAD_PORT,
}


/**
 * Adds additional host:port pair as TCP relay.
 *
 * This function can be used to initiate TCP connections to different ports on
 * the same bootstrap node, or to add TCP relays without using them as
 * bootstrap nodes.
 *
 * @param host The hostname or IP address (IPv4 or IPv6) of the TCP relay.
 *   Must be at most $MAX_HOSTNAME_LENGTH chars, including the NUL byte.
 * @param port The port on the host on which the TCP relay is listening.
 * @param public_key The long term public key of the TCP relay
 *   ($PUBLIC_KEY_SIZE bytes).
 * @return true on success.
 */
bool add_tcp_relay(string host, uint16_t port, const uint8_t[PUBLIC_KEY_SIZE] public_key)
    with error for bootstrap;


/**
 * Protocols that can be used to connect to the network or friends.
 *
 * @deprecated All UPPER_CASE enum type names are deprecated. Use the
 *   Camel_Snake_Case versions, instead.
 */
enum class CONNECTION {
  /**
   * There is no connection. This instance, or the friend the state change is
   * about, is now offline.
   */
  NONE,
  /**
   * A TCP connection has been established. For the own instance, this means it
   * is connected through a TCP relay, only. For a friend, this means that the
   * connection to that particular friend goes through a TCP relay.
   */
  TCP,
  /**
   * A UDP connection has been established. For the own instance, this means it
   * is able to send UDP packets to DHT nodes, but may still be connected to
   * a TCP relay. For a friend, this means that the connection to that
   * particular friend was built using direct UDP packets.
   */
  UDP,
}


namespace self {

  CONNECTION connection_status {
    /**
     * Return whether we are connected to the DHT. The return value is equal to the
     * last value received through the `${event connection_status}` callback.
     *
     * @deprecated This getter is deprecated. Use the event and store the status
     * in the client state.
     */
    get();
  }


  /**
   * This event is triggered whenever there is a change in the DHT connection
   * state. When disconnected, a client may choose to call $bootstrap again, to
   * reconnect to the DHT. Note that this state may frequently change for short
   * amounts of time. Clients should therefore not immediately bootstrap on
   * receiving a disconnect.
   *
   * TODO(iphydf): how long should a client wait before bootstrapping again?
   */
  event connection_status const {
    /**
     * @param connection_status Whether we are connected to the DHT.
     */
    typedef void(CONNECTION connection_status);
  }

}


/**
 * Return the time in milliseconds before $iterate() should be called again
 * for optimal performance.
 */
const uint32_t iteration_interval();


/**
 * The main loop that needs to be run in intervals of $iteration_interval()
 * milliseconds.
 */
void iterate(any user_data);


/*******************************************************************************
 *
 * :: Internal client information (Tox address/id)
 *
 ******************************************************************************/


namespace self {

  uint8_t[ADDRESS_SIZE] address {
    /**
     * Writes the Tox friend address of the client to a byte array. The address is
     * not in human-readable format. If a client wants to display the address,
     * formatting is required.
     *
     * @param address A memory region of at least $ADDRESS_SIZE bytes. If this
     *   parameter is NULL, this function has no effect.
     * @see $ADDRESS_SIZE for the address format.
     */
    get();
  }


  uint32_t nospam {
    /**
     * Set the 4-byte nospam part of the address. This value is expected in host
     * byte order. I.e. 0x12345678 will form the bytes [12, 34, 56, 78] in the
     * nospam part of the Tox friend address.
     *
     * @param nospam Any 32 bit unsigned integer.
     */
    set();

    /**
     * Get the 4-byte nospam part of the address. This value is returned in host
     * byte order.
     */
    get();
  }


  uint8_t[PUBLIC_KEY_SIZE] public_key {
    /**
     * Copy the Tox Public Key (long term) from the Tox object.
     *
     * @param public_key A memory region of at least $PUBLIC_KEY_SIZE bytes. If
     *   this parameter is NULL, this function has no effect.
     */
    get();
  }


  uint8_t[SECRET_KEY_SIZE] secret_key {
    /**
     * Copy the Tox Secret Key from the Tox object.
     *
     * @param secret_key A memory region of at least $SECRET_KEY_SIZE bytes. If
     *   this parameter is NULL, this function has no effect.
     */
    get();
  }

}


/*******************************************************************************
 *
 * :: User-visible client information (nickname/status)
 *
 ******************************************************************************/


/**
 * Common error codes for all functions that set a piece of user-visible
 * client information.
 */
error for set_info {
  NULL,
  /**
   * Information length exceeded maximum permissible size.
   */
  TOO_LONG,
}


namespace self {

  uint8_t[length <= MAX_NAME_LENGTH] name {
    /**
     * Set the nickname for the Tox client.
     *
     * Nickname length cannot exceed $MAX_NAME_LENGTH. If length is 0, the name
     * parameter is ignored (it can be NULL), and the nickname is set back to empty.
     *
     * @param name A byte array containing the new nickname.
     * @param length The size of the name byte array.
     *
     * @return true on success.
     */
    set() with error for set_info;

    /**
     * Return the length of the current nickname as passed to $set.
     *
     * If no nickname was set before calling this function, the name is empty,
     * and this function returns 0.
     *
     * @see threading for concurrency implications.
     */
    size();

    /**
     * Write the nickname set by $set to a byte array.
     *
     * If no nickname was set before calling this function, the name is empty,
     * and this function has no effect.
     *
     * Call $size to find out how much memory to allocate for
     * the result.
     *
     * @param name A valid memory location large enough to hold the nickname.
     *   If this parameter is NULL, the function has no effect.
     */
    get();
  }


  uint8_t[length <= MAX_STATUS_MESSAGE_LENGTH] status_message {
    /**
     * Set the client's status message.
     *
     * Status message length cannot exceed $MAX_STATUS_MESSAGE_LENGTH. If
     * length is 0, the status parameter is ignored (it can be NULL), and the
     * user status is set back to empty.
     */
    set() with error for set_info;

    /**
     * Return the length of the current status message as passed to $set.
     *
     * If no status message was set before calling this function, the status
     * is empty, and this function returns 0.
     *
     * @see threading for concurrency implications.
     */
    size();

    /**
     * Write the status message set by $set to a byte array.
     *
     * If no status message was set before calling this function, the status is
     * empty, and this function has no effect.
     *
     * Call $size to find out how much memory to allocate for
     * the result.
     *
     * @param status_message A valid memory location large enough to hold the
     *   status message. If this parameter is NULL, the function has no effect.
     */
    get();
  }


  USER_STATUS status {
    /**
     * Set the client's user status.
     *
     * @param status One of the user statuses listed in the enumeration above.
     */
    set();

    /**
     * Returns the client's user status.
     */
    get();
  }

}


/*******************************************************************************
 *
 * :: Friend list management
 *
 ******************************************************************************/


namespace friend {

  /**
   * Add a friend to the friend list and send a friend request.
   *
   * A friend request message must be at least 1 byte long and at most
   * $MAX_FRIEND_REQUEST_LENGTH.
   *
   * Friend numbers are unique identifiers used in all functions that operate on
   * friends. Once added, a friend number is stable for the lifetime of the Tox
   * object. After saving the state and reloading it, the friend numbers may not
   * be the same as before. Deleting a friend creates a gap in the friend number
   * set, which is filled by the next adding of a friend. Any pattern in friend
   * numbers should not be relied on.
   *
   * If more than INT32_MAX friends are added, this function causes undefined
   * behaviour.
   *
   * @param address The address of the friend (returned by ${self.address.get} of
   *   the friend you wish to add) it must be $ADDRESS_SIZE bytes.
   * @param message The message that will be sent along with the friend request.
   * @param length The length of the data byte array.
   *
   * @return the friend number on success, an unspecified value on failure.
   */
  uint32_t add(
      const uint8_t[ADDRESS_SIZE] address,
      const uint8_t[length <= MAX_FRIEND_REQUEST_LENGTH] message
  ) {
    NULL,
    /**
     * The length of the friend request message exceeded
     * $MAX_FRIEND_REQUEST_LENGTH.
     */
    TOO_LONG,
    /**
     * The friend request message was empty. This, and the TOO_LONG code will
     * never be returned from $add_norequest.
     */
    NO_MESSAGE,
    /**
     * The friend address belongs to the sending client.
     */
    OWN_KEY,
    /**
     * A friend request has already been sent, or the address belongs to a friend
     * that is already on the friend list.
     */
    ALREADY_SENT,
    /**
     * The friend address checksum failed.
     */
    BAD_CHECKSUM,
    /**
     * The friend was already there, but the nospam value was different.
     */
    SET_NEW_NOSPAM,
    /**
     * A memory allocation failed when trying to increase the friend list size.
     */
    MALLOC,
  }


  /**
   * Add a friend without sending a friend request.
   *
   * This function is used to add a friend in response to a friend request. If the
   * client receives a friend request, it can be reasonably sure that the other
   * client added this client as a friend, eliminating the need for a friend
   * request.
   *
   * This function is also useful in a situation where both instances are
   * controlled by the same entity, so that this entity can perform the mutual
   * friend adding. In this case, there is no need for a friend request, either.
   *
   * @param public_key A byte array of length $PUBLIC_KEY_SIZE containing the
   *   Public Key (not the Address) of the friend to add.
   *
   * @return the friend number on success, an unspecified value on failure.
   * @see $add for a more detailed description of friend numbers.
   */
  uint32_t add_norequest(const uint8_t[PUBLIC_KEY_SIZE] public_key)
      with error for add;


  /**
   * Remove a friend from the friend list.
   *
   * This does not notify the friend of their deletion. After calling this
   * function, this client will appear offline to the friend and no communication
   * can occur between the two.
   *
   * @param friend_number Friend number for the friend to be deleted.
   *
   * @return true on success.
   */
  bool delete(uint32_t friend_number) {
    /**
     * There was no friend with the given friend number. No friends were deleted.
     */
    FRIEND_NOT_FOUND,
  }

}


/*******************************************************************************
 *
 * :: Friend list queries
 *
 ******************************************************************************/

namespace friend {

  /**
   * Return the friend number associated with that Public Key.
   *
   * @return the friend number on success, an unspecified value on failure.
   * @param public_key A byte array containing the Public Key.
   */
  const uint32_t by_public_key(const uint8_t[PUBLIC_KEY_SIZE] public_key) {
    NULL,
    /**
     * No friend with the given Public Key exists on the friend list.
     */
    NOT_FOUND,
  }


  /**
   * Checks if a friend with the given friend number exists and returns true if
   * it does.
   */
  const bool exists(uint32_t friend_number);

}

namespace self {

  uint32_t[size] friend_list {
    /**
     * Return the number of friends on the friend list.
     *
     * This function can be used to determine how much memory to allocate for
     * $get.
     */
    size();


    /**
     * Copy a list of valid friend numbers into an array.
     *
     * Call $size to determine the number of elements to allocate.
     *
     * @param friend_list A memory region with enough space to hold the friend
     *   list. If this parameter is NULL, this function has no effect.
     */
    get();
  }

}



namespace friend {

  uint8_t[PUBLIC_KEY_SIZE] public_key {
    /**
     * Copies the Public Key associated with a given friend number to a byte array.
     *
     * @param friend_number The friend number you want the Public Key of.
     * @param public_key A memory region of at least $PUBLIC_KEY_SIZE bytes. If
     *   this parameter is NULL, this function has no effect.
     *
     * @return true on success.
     */
    get(uint32_t friend_number) {
      /**
       * No friend with the given number exists on the friend list.
       */
      FRIEND_NOT_FOUND,
    }
  }

}

namespace friend {

  uint64_t last_online {
    /**
     * Return a unix-time timestamp of the last time the friend associated with a given
     * friend number was seen online. This function will return UINT64_MAX on error.
     *
     * @param friend_number The friend number you want to query.
     */
    get(uint32_t friend_number) {
      /**
       * No friend with the given number exists on the friend list.
       */
      FRIEND_NOT_FOUND,
    }
  }

}

/*******************************************************************************
 *
 * :: Friend-specific state queries (can also be received through callbacks)
 *
 ******************************************************************************/


namespace friend {

  /**
   * Common error codes for friend state query functions.
   */
  error for query {
    /**
     * The pointer parameter for storing the query result (name, message) was
     * NULL. Unlike the `_self_` variants of these functions, which have no effect
     * when a parameter is NULL, these functions return an error in that case.
     */
    NULL,
    /**
     * The friend_number did not designate a valid friend.
     */
    FRIEND_NOT_FOUND,
  }


  uint8_t[length <= MAX_NAME_LENGTH] name {
    /**
     * Return the length of the friend's name. If the friend number is invalid, the
     * return value is unspecified.
     *
     * The return value is equal to the `length` argument received by the last
     * `${event name}` callback.
     */
    size(uint32_t friend_number)
        with error for query;

    /**
     * Write the name of the friend designated by the given friend number to a byte
     * array.
     *
     * Call $size to determine the allocation size for the `name`
     * parameter.
     *
     * The data written to `name` is equal to the data received by the last
     * `${event name}` callback.
     *
     * @param name A valid memory region large enough to store the friend's name.
     *
     * @return true on success.
     */
    get(uint32_t friend_number)
        with error for query;
  }


  /**
   * This event is triggered when a friend changes their name.
   */
  event name const {
    /**
     * @param friend_number The friend number of the friend whose name changed.
     * @param name A byte array containing the same data as
     *   ${name.get} would write to its `name` parameter.
     * @param length A value equal to the return value of
     *   ${name.size}.
     */
    typedef void(uint32_t friend_number, const uint8_t[length <= MAX_NAME_LENGTH] name);
  }


  uint8_t[length <= MAX_STATUS_MESSAGE_LENGTH] status_message {
    /**
     * Return the length of the friend's status message. If the friend number is
     * invalid, the return value is SIZE_MAX.
     */
    size(uint32_t friend_number)
        with error for query;

    /**
     * Write the status message of the friend designated by the given friend number to a byte
     * array.
     *
     * Call $size to determine the allocation size for the `status_message`
     * parameter.
     *
     * The data written to `status_message` is equal to the data received by the last
     * `${event status_message}` callback.
     *
     * @param status_message A valid memory region large enough to store the friend's status message.
     */
    get(uint32_t friend_number)
        with error for query;
  }


  /**
   * This event is triggered when a friend changes their status message.
   */
  event status_message const {
    /**
     * @param friend_number The friend number of the friend whose status message
     *   changed.
     * @param message A byte array containing the same data as
     *   ${status_message.get} would write to its `status_message` parameter.
     * @param length A value equal to the return value of
     *   ${status_message.size}.
     */
    typedef void(uint32_t friend_number, const uint8_t[length <= MAX_STATUS_MESSAGE_LENGTH] message);
  }


  USER_STATUS status {
    /**
     * Return the friend's user status (away/busy/...). If the friend number is
     * invalid, the return value is unspecified.
     *
     * The status returned is equal to the last status received through the
     * `${event status}` callback.
     *
     * @deprecated This getter is deprecated. Use the event and store the status
     *   in the client state.
     */
    get(uint32_t friend_number)
        with error for query;
  }


  /**
   * This event is triggered when a friend changes their user status.
   */
  event status const {
    /**
     * @param friend_number The friend number of the friend whose user status
     *   changed.
     * @param status The new user status.
     */
    typedef void(uint32_t friend_number, USER_STATUS status);
  }


  CONNECTION connection_status {
    /**
     * Check whether a friend is currently connected to this client.
     *
     * The result of this function is equal to the last value received by the
     * `${event connection_status}` callback.
     *
     * @param friend_number The friend number for which to query the connection
     *   status.
     *
     * @return the friend's connection status as it was received through the
     *   `${event connection_status}` event.
     *
     * @deprecated This getter is deprecated. Use the event and store the status
     *   in the client state.
     */
    get(uint32_t friend_number)
        with error for query;
  }


  /**
   * This event is triggered when a friend goes offline after having been online,
   * or when a friend goes online.
   *
   * This callback is not called when adding friends. It is assumed that when
   * adding friends, their connection status is initially offline.
   */
  event connection_status const {
    /**
     * @param friend_number The friend number of the friend whose connection status
     *   changed.
     * @param connection_status The result of calling
     *   ${connection_status.get} on the passed friend_number.
     */
    typedef void(uint32_t friend_number, CONNECTION connection_status);
  }


  bool typing {
    /**
     * Check whether a friend is currently typing a message.
     *
     * @param friend_number The friend number for which to query the typing status.
     *
     * @return true if the friend is typing.
     * @return false if the friend is not typing, or the friend number was
     *   invalid. Inspect the error code to determine which case it is.
     *
     * @deprecated This getter is deprecated. Use the event and store the status
     *   in the client state.
     */
    get(uint32_t friend_number)
        with error for query;
  }


  /**
   * This event is triggered when a friend starts or stops typing.
   */
  event typing const {
    /**
     * @param friend_number The friend number of the friend who started or stopped
     *   typing.
     * @param is_typing The result of calling ${typing.get} on the passed
     *   friend_number.
     */
    typedef void(uint32_t friend_number, bool is_typing);
  }

}


/*******************************************************************************
 *
 * :: Sending private messages
 *
 ******************************************************************************/

error for set_typing {
  /**
   * The friend number did not designate a valid friend.
   */
  FRIEND_NOT_FOUND,
}

namespace self {

  bool typing {
    /**
     * Set the client's typing status for a friend.
     *
     * The client is responsible for turning it on or off.
     *
     * @param friend_number The friend to which the client is typing a message.
     * @param typing The typing status. True means the client is typing.
     *
     * @return true on success.
     */
    set(uint32_t friend_number) with error for set_typing;
  }

}


namespace friend {

  namespace send {

    /**
     * Send a text chat message to an online friend.
     *
     * This function creates a chat message packet and pushes it into the send
     * queue.
     *
     * The message length may not exceed $MAX_MESSAGE_LENGTH. Larger messages
     * must be split by the client and sent as separate messages. Other clients can
     * then reassemble the fragments. Messages may not be empty.
     *
     * The return value of this function is the message ID. If a read receipt is
     * received, the triggered `${event read_receipt}` event will be passed this message ID.
     *
     * Message IDs are unique per friend. The first message ID is 0. Message IDs are
     * incremented by 1 each time a message is sent. If UINT32_MAX messages were
     * sent, the next message ID is 0.
     *
     * @param type Message type (normal, action, ...).
     * @param friend_number The friend number of the friend to send the message to.
     * @param message A non-NULL pointer to the first element of a byte array
     *   containing the message text.
     * @param length Length of the message to be sent.
     */
    uint32_t message(uint32_t friend_number, MESSAGE_TYPE type,
                     const uint8_t[length <= MAX_MESSAGE_LENGTH] message) {
      NULL,
      /**
       * The friend number did not designate a valid friend.
       */
      FRIEND_NOT_FOUND,
      /**
       * This client is currently not connected to the friend.
       */
      FRIEND_NOT_CONNECTED,
      /**
       * An allocation error occurred while increasing the send queue size.
       */
      SENDQ,
      /**
       * Message length exceeded $MAX_MESSAGE_LENGTH.
       */
      TOO_LONG,
      /**
       * Attempted to send a zero-length message.
       */
      EMPTY,
    }

  }


  /**
   * This event is triggered when the friend receives the message sent with
   * ${send.message} with the corresponding message ID.
   */
  event read_receipt const {
    /**
     * @param friend_number The friend number of the friend who received the message.
     * @param message_id The message ID as returned from ${send.message}
     *   corresponding to the message sent.
     */
    typedef void(uint32_t friend_number, uint32_t message_id);
  }

}


/*******************************************************************************
 *
 * :: Receiving private messages and friend requests
 *
 ******************************************************************************/


namespace friend {

  /**
   * This event is triggered when a friend request is received.
   */
  event request const {
    /**
     * @param public_key The Public Key of the user who sent the friend request.
     * @param message The message they sent along with the request.
     * @param length The size of the message byte array.
     */
    typedef void(const uint8_t[PUBLIC_KEY_SIZE] public_key,
                 const uint8_t[length <= MAX_MESSAGE_LENGTH] message);
  }


  /**
   * This event is triggered when a message from a friend is received.
   */
  event message const {
    /**
     * @param friend_number The friend number of the friend who sent the message.
     * @param message The message data they sent.
     * @param length The size of the message byte array.
     */
    typedef void(uint32_t friend_number, MESSAGE_TYPE type,
                 const uint8_t[length <= MAX_MESSAGE_LENGTH] message);
  }

}


/*******************************************************************************
 *
 * :: File transmission: common between sending and receiving
 *
 ******************************************************************************/


/**
 * Generates a cryptographic hash of the given data.
 *
 * This function may be used by clients for any purpose, but is provided
 * primarily for validating cached avatars. This use is highly recommended to
 * avoid unnecessary avatar updates.
 *
 * If hash is NULL or data is NULL while length is not 0 the function returns false,
 * otherwise it returns true.
 *
 * This function is a wrapper to internal message-digest functions.
 *
 * @param hash A valid memory location the hash data. It must be at least
 *   $HASH_LENGTH bytes in size.
 * @param data Data to be hashed or NULL.
 * @param length Size of the data array or 0.
 *
 * @return true if hash was not NULL.
 */
static bool hash(uint8_t[HASH_LENGTH] hash, const uint8_t[length] data);


namespace file {

  /**
   * A list of pre-defined file kinds. Toxcore itself does not behave
   * differently for different file kinds. These are a hint to the client
   * telling it what use the sender intended for the file. The `kind` parameter
   * in the send function and recv callback are `uint32_t`, not $KIND, because
   * clients can invent their own file kind. Unknown file kinds should be
   * treated as ${KIND.DATA}.
   */
  enum KIND {
    /**
     * Arbitrary file data. Clients can choose to handle it based on the file name
     * or magic or any other way they choose.
     */
    DATA,
    /**
     * Avatar file_id. This consists of $hash(image).
     * Avatar data. This consists of the image data.
     *
     * Avatars can be sent at any time the client wishes. Generally, a client will
     * send the avatar to a friend when that friend comes online, and to all
     * friends when the avatar changed. A client can save some traffic by
     * remembering which friend received the updated avatar already and only send
     * it if the friend has an out of date avatar.
     *
     * Clients who receive avatar send requests can reject it (by sending
     * ${CONTROL.CANCEL} before any other controls), or accept it (by
     * sending ${CONTROL.RESUME}). The file_id of length $HASH_LENGTH bytes
     * (same length as $FILE_ID_LENGTH) will contain the hash. A client can compare
     * this hash with a saved hash and send ${CONTROL.CANCEL} to terminate the avatar
     * transfer if it matches.
     *
     * When file_size is set to 0 in the transfer request it means that the client
     * has no avatar.
     */
    AVATAR,
  }


  enum class CONTROL {
    /**
     * Sent by the receiving side to accept a file send request. Also sent after a
     * $PAUSE command to continue sending or receiving.
     */
    RESUME,
    /**
     * Sent by clients to pause the file transfer. The initial state of a file
     * transfer is always paused on the receiving side and running on the sending
     * side. If both the sending and receiving side pause the transfer, then both
     * need to send $RESUME for the transfer to resume.
     */
    PAUSE,
    /**
     * Sent by the receiving side to reject a file send request before any other
     * commands are sent. Also sent by either side to terminate a file transfer.
     */
    CANCEL,
  }


  /**
   * Sends a file control command to a friend for a given file transfer.
   *
   * @param friend_number The friend number of the friend the file is being
   *   transferred to or received from.
   * @param file_number The friend-specific identifier for the file transfer.
   * @param control The control command to send.
   *
   * @return true on success.
   */
  bool control(uint32_t friend_number, uint32_t file_number, CONTROL control) {
    /**
     * The friend_number passed did not designate a valid friend.
     */
    FRIEND_NOT_FOUND,
    /**
     * This client is currently not connected to the friend.
     */
    FRIEND_NOT_CONNECTED,
    /**
     * No file transfer with the given file number was found for the given friend.
     */
    NOT_FOUND,
    /**
     * A RESUME control was sent, but the file transfer is running normally.
     */
    NOT_PAUSED,
    /**
     * A RESUME control was sent, but the file transfer was paused by the other
     * party. Only the party that paused the transfer can resume it.
     */
    DENIED,
    /**
     * A PAUSE control was sent, but the file transfer was already paused.
     */
    ALREADY_PAUSED,
    /**
     * Packet queue is full.
     */
    SENDQ,
  }


  /**
   * This event is triggered when a file control command is received from a
   * friend.
   */
  event recv_control const {
    /**
     * When receiving ${CONTROL.CANCEL}, the client should release the
     * resources associated with the file number and consider the transfer failed.
     *
     * @param friend_number The friend number of the friend who is sending the file.
     * @param file_number The friend-specific file number the data received is
     *   associated with.
     * @param control The file control command received.
     */
    typedef void(uint32_t friend_number, uint32_t file_number, CONTROL control);
  }

  /**
   * Sends a file seek control command to a friend for a given file transfer.
   *
   * This function can only be called to resume a file transfer right before
   * ${CONTROL.RESUME} is sent.
   *
   * @param friend_number The friend number of the friend the file is being
   *   received from.
   * @param file_number The friend-specific identifier for the file transfer.
   * @param position The position that the file should be seeked to.
   */
  bool seek(uint32_t friend_number, uint32_t file_number, uint64_t position) {
    /**
     * The friend_number passed did not designate a valid friend.
     */
    FRIEND_NOT_FOUND,
    /**
     * This client is currently not connected to the friend.
     */
    FRIEND_NOT_CONNECTED,
    /**
     * No file transfer with the given file number was found for the given friend.
     */
    NOT_FOUND,
    /**
     * File was not in a state where it could be seeked.
     */
    DENIED,
    /**
     * Seek position was invalid
     */
    INVALID_POSITION,
    /**
     * Packet queue is full.
     */
    SENDQ,
  }


  error for get {
    NULL,
    /**
     * The friend_number passed did not designate a valid friend.
     */
    FRIEND_NOT_FOUND,
    /**
     * No file transfer with the given file number was found for the given friend.
     */
    NOT_FOUND,
  }

  uint8_t[FILE_ID_LENGTH] file_id {
    /**
     * Copy the file id associated to the file transfer to a byte array.
     *
     * @param friend_number The friend number of the friend the file is being
     *   transferred to or received from.
     * @param file_number The friend-specific identifier for the file transfer.
     * @param file_id A memory region of at least $FILE_ID_LENGTH bytes. If
     *   this parameter is NULL, this function has no effect.
     *
     * @return true on success.
     */
    get(uint32_t friend_number, uint32_t file_number)
        with error for get;
  }

}


/*******************************************************************************
 *
 * :: File transmission: sending
 *
 ******************************************************************************/


namespace file {

  /**
   * Send a file transmission request.
   *
   * Maximum filename length is $MAX_FILENAME_LENGTH bytes. The filename
   * should generally just be a file name, not a path with directory names.
   *
   * If a non-UINT64_MAX file size is provided, it can be used by both sides to
   * determine the sending progress. File size can be set to UINT64_MAX for streaming
   * data of unknown size.
   *
   * File transmission occurs in chunks, which are requested through the
   * `${event chunk_request}` event.
   *
   * When a friend goes offline, all file transfers associated with the friend are
   * purged from core.
   *
   * If the file contents change during a transfer, the behaviour is unspecified
   * in general. What will actually happen depends on the mode in which the file
   * was modified and how the client determines the file size.
   *
   * - If the file size was increased
   *   - and sending mode was streaming (file_size = UINT64_MAX), the behaviour
   *     will be as expected.
   *   - and sending mode was file (file_size != UINT64_MAX), the
   *     ${event chunk_request} callback will receive length = 0 when Core thinks
   *     the file transfer has finished. If the client remembers the file size as
   *     it was when sending the request, it will terminate the transfer normally.
   *     If the client re-reads the size, it will think the friend cancelled the
   *     transfer.
   * - If the file size was decreased
   *   - and sending mode was streaming, the behaviour is as expected.
   *   - and sending mode was file, the callback will return 0 at the new
   *     (earlier) end-of-file, signalling to the friend that the transfer was
   *     cancelled.
   * - If the file contents were modified
   *   - at a position before the current read, the two files (local and remote)
   *     will differ after the transfer terminates.
   *   - at a position after the current read, the file transfer will succeed as
   *     expected.
   *   - In either case, both sides will regard the transfer as complete and
   *     successful.
   *
   * @param friend_number The friend number of the friend the file send request
   *   should be sent to.
   * @param kind The meaning of the file to be sent.
   * @param file_size Size in bytes of the file the client wants to send, UINT64_MAX if
   *   unknown or streaming.
   * @param file_id A file identifier of length $FILE_ID_LENGTH that can be used to
   *   uniquely identify file transfers across core restarts. If NULL, a random one will
   *   be generated by core. It can then be obtained by using ${file_id.get}().
   * @param filename Name of the file. Does not need to be the actual name. This
   *   name will be sent along with the file send request.
   * @param filename_length Size in bytes of the filename.
   *
   * @return A file number used as an identifier in subsequent callbacks. This
   *   number is per friend. File numbers are reused after a transfer terminates.
   *   On failure, this function returns an unspecified value. Any pattern in file numbers
   *   should not be relied on.
   */
  uint32_t send(uint32_t friend_number, uint32_t kind, uint64_t file_size,
                const uint8_t[FILE_ID_LENGTH] file_id,
                const uint8_t[filename_length <= MAX_FILENAME_LENGTH] filename) {
    NULL,
    /**
     * The friend_number passed did not designate a valid friend.
     */
    FRIEND_NOT_FOUND,
    /**
     * This client is currently not connected to the friend.
     */
    FRIEND_NOT_CONNECTED,
    /**
     * Filename length exceeded $MAX_FILENAME_LENGTH bytes.
     */
    NAME_TOO_LONG,
    /**
     * Too many ongoing transfers. The maximum number of concurrent file transfers
     * is 256 per friend per direction (sending and receiving).
     */
    TOO_MANY,
  }


  /**
   * Send a chunk of file data to a friend.
   *
   * This function is called in response to the `${event chunk_request}` callback. The
   * length parameter should be equal to the one received though the callback.
   * If it is zero, the transfer is assumed complete. For files with known size,
   * Core will know that the transfer is complete after the last byte has been
   * received, so it is not necessary (though not harmful) to send a zero-length
   * chunk to terminate. For streams, core will know that the transfer is finished
   * if a chunk with length less than the length requested in the callback is sent.
   *
   * @param friend_number The friend number of the receiving friend for this file.
   * @param file_number The file transfer identifier returned by tox_file_send.
   * @param position The file or stream position from which to continue reading.
   * @return true on success.
   */
  bool send_chunk(uint32_t friend_number, uint32_t file_number, uint64_t position, const uint8_t[length] data) {
    /**
     * The length parameter was non-zero, but data was NULL.
     */
    NULL,
    /**
     * The friend_number passed did not designate a valid friend.
     */
    FRIEND_NOT_FOUND,
    /**
     * This client is currently not connected to the friend.
     */
    FRIEND_NOT_CONNECTED,
    /**
     * No file transfer with the given file number was found for the given friend.
     */
    NOT_FOUND,
    /**
     * File transfer was found but isn't in a transferring state: (paused, done,
     * broken, etc...) (happens only when not called from the request chunk callback).
     */
    NOT_TRANSFERRING,
    /**
     * Attempted to send more or less data than requested. The requested data size is
     * adjusted according to maximum transmission unit and the expected end of
     * the file. Trying to send less or more than requested will return this error.
     */
    INVALID_LENGTH,
    /**
     * Packet queue is full.
     */
    SENDQ,
    /**
     * Position parameter was wrong.
     */
    WRONG_POSITION,
  }


  /**
   * This event is triggered when Core is ready to send more file data.
   */
  event chunk_request const {
    /**
     * If the length parameter is 0, the file transfer is finished, and the client's
     * resources associated with the file number should be released. After a call
     * with zero length, the file number can be reused for future file transfers.
     *
     * If the requested position is not equal to the client's idea of the current
     * file or stream position, it will need to seek. In case of read-once streams,
     * the client should keep the last read chunk so that a seek back can be
     * supported. A seek-back only ever needs to read from the last requested chunk.
     * This happens when a chunk was requested, but the send failed. A seek-back
     * request can occur an arbitrary number of times for any given chunk.
     *
     * In response to receiving this callback, the client should call the function
     * `$send_chunk` with the requested chunk. If the number of bytes sent
     * through that function is zero, the file transfer is assumed complete. A
     * client must send the full length of data requested with this callback.
     *
     * @param friend_number The friend number of the receiving friend for this file.
     * @param file_number The file transfer identifier returned by $send.
     * @param position The file or stream position from which to continue reading.
     * @param length The number of bytes requested for the current chunk.
     */
    typedef void(uint32_t friend_number, uint32_t file_number, uint64_t position, size_t length);
  }

}


/*******************************************************************************
 *
 * :: File transmission: receiving
 *
 ******************************************************************************/


namespace file {

  /**
   * This event is triggered when a file transfer request is received.
   */
  event recv const {
    /**
     * The client should acquire resources to be associated with the file transfer.
     * Incoming file transfers start in the PAUSED state. After this callback
     * returns, a transfer can be rejected by sending a ${CONTROL.CANCEL}
     * control command before any other control commands. It can be accepted by
     * sending ${CONTROL.RESUME}.
     *
     * @param friend_number The friend number of the friend who is sending the file
     *   transfer request.
     * @param file_number The friend-specific file number the data received is
     *   associated with.
     * @param kind The meaning of the file that was sent.
     * @param file_size Size in bytes of the file the client wants to send,
     *   UINT64_MAX if unknown or streaming.
     * @param filename Name of the file. Does not need to be the actual name. This
     *   name will be sent along with the file send request.
     * @param filename_length Size in bytes of the filename.
     */
    typedef void(uint32_t friend_number, uint32_t file_number, uint32_t kind,
                 uint64_t file_size, const uint8_t[filename_length <= MAX_FILENAME_LENGTH] filename);
  }


  /**
   * This event is first triggered when a file transfer request is received, and
   * subsequently when a chunk of file data for an accepted request was received.
   */
  event recv_chunk const {
    /**
     * When length is 0, the transfer is finished and the client should release the
     * resources it acquired for the transfer. After a call with length = 0, the
     * file number can be reused for new file transfers.
     *
     * If position is equal to file_size (received in the file_receive callback)
     * when the transfer finishes, the file was received completely. Otherwise, if
     * file_size was UINT64_MAX, streaming ended successfully when length is 0.
     *
     * @param friend_number The friend number of the friend who is sending the file.
     * @param file_number The friend-specific file number the data received is
     *   associated with.
     * @param position The file position of the first byte in data.
     * @param data A byte array containing the received chunk.
     * @param length The length of the received chunk.
     */
    typedef void(uint32_t friend_number, uint32_t file_number, uint64_t position,
                 const uint8_t[length] data);
  }

}


/*******************************************************************************
 *
 * :: Conference management
 *
 ******************************************************************************/

namespace conference {

  /**
   * Conference types for the ${event invite} event.
   *
   * @deprecated All UPPER_CASE enum type names are deprecated. Use the
   *   Camel_Snake_Case versions, instead.
   */
  enum class TYPE {
    /**
     * Text-only conferences that must be accepted with the $join function.
     */
    TEXT,
    /**
     * Video conference. The function to accept these is in toxav.
     */
    AV,
  }


  /**
   * This event is triggered when the client is invited to join a conference.
   */
  event invite const {
    /**
     * The invitation will remain valid until the inviting friend goes offline
     * or exits the conference.
     *
     * @param friend_number The friend who invited us.
     * @param type The conference type (text only or audio/video).
     * @param cookie A piece of data of variable length required to join the
     *   conference.
     * @param length The length of the cookie.
     */
    typedef void(uint32_t friend_number, TYPE type, const uint8_t[length] cookie);
  }


  /**
   * This event is triggered when the client successfully connects to a
   * conference after joining it with the $join function.
   */
  event connected const {
    /**
     * @param conference_number The conference number of the conference to which we have connected.
     */
    typedef void(uint32_t conference_number);
  }


  /**
   * This event is triggered when the client receives a conference message.
   */
  event message const {
    /**
     * @param conference_number The conference number of the conference the message is intended for.
     * @param peer_number The ID of the peer who sent the message.
     * @param type The type of message (normal, action, ...).
     * @param message The message data.
     * @param length The length of the message.
     */
    typedef void(uint32_t conference_number, uint32_t peer_number, MESSAGE_TYPE type,
                 const uint8_t[length] message);
  }


  /**
   * This event is triggered when a peer changes the conference title.
   *
   * If peer_number == UINT32_MAX, then author is unknown (e.g. initial joining the conference).
   */
  event title const {
    /**
     * @param conference_number The conference number of the conference the title change is intended for.
     * @param peer_number The ID of the peer who changed the title.
     * @param title The title data.
     * @param length The title length.
     */
    typedef void(uint32_t conference_number, uint32_t peer_number, const uint8_t[length] title);
  }

  namespace peer {

    /**
     * This event is triggered when a peer changes their name.
     */
    event name const {
      /**
       * @param conference_number The conference number of the conference the
       *   peer is in.
       * @param peer_number The ID of the peer who changed their nickname.
       * @param name A byte array containing the new nickname.
       * @param length The size of the name byte array.
       */
      typedef void(uint32_t conference_number, uint32_t peer_number, const uint8_t[length] name);
    }

    /**
     * This event is triggered when a peer joins or leaves the conference.
     */
    event list_changed const {
      /**
       * @param conference_number The conference number of the conference the
       *   peer is in.
       */
      typedef void(uint32_t conference_number);
    }

  }


  /**
   * Creates a new conference.
   *
   * This function creates and connects to a new text conference.
   *
   * @return conference number on success, or an unspecified value on failure.
   */
  uint32_t new() {
    /**
     * The conference instance failed to initialize.
     */
    INIT,
  }

  /**
   * This function deletes a conference.
   *
   * @param conference_number The conference number of the conference to be deleted.
   *
   * @return true on success.
   */
  bool delete(uint32_t conference_number) {
    /**
     * The conference number passed did not designate a valid conference.
     */
    CONFERENCE_NOT_FOUND,
  }

  /**
   * Error codes for peer info queries.
   */
  error for peer_query {
    /**
     * The conference number passed did not designate a valid conference.
     */
    CONFERENCE_NOT_FOUND,
    /**
     * The peer number passed did not designate a valid peer.
     */
    PEER_NOT_FOUND,
    /**
     * The client is not connected to the conference.
     */
    NO_CONNECTION,
  }


  namespace peer {

    /**
     * Return the number of online peers in the conference. The unsigned
     * integers less than this number are the valid values of peer_number for
     * the functions querying these peers. Return value is unspecified on
     * failure.
     */
    const uint32_t count(uint32_t conference_number)
        with error for peer_query;

    uint8_t[size] name {

      /**
       * Return the length of the peer's name. Return value is unspecified on failure.
       */
      size(uint32_t conference_number, uint32_t peer_number)
          with error for peer_query;

      /**
       * Copy the name of peer_number who is in conference_number to name.
       *
       * Call $size to determine the allocation size for the `name` parameter.
       *
       * @param name A valid memory region large enough to store the peer's name.
       *
       * @return true on success.
       */
      get(uint32_t conference_number, uint32_t peer_number)
          with error for peer_query;
    }

    /**
     * Copy the public key of peer_number who is in conference_number to public_key.
     * public_key must be $PUBLIC_KEY_SIZE long.
     *
     * @return true on success.
     */
    uint8_t[PUBLIC_KEY_SIZE] public_key {
      get(uint32_t conference_number, uint32_t peer_number)
          with error for peer_query;
    }

    /**
     * Return true if passed peer_number corresponds to our own.
     */
    const bool number_is_ours(uint32_t conference_number, uint32_t peer_number)
        with error for peer_query;

  }

  namespace offline_peer {

    /**
     * Return the number of offline peers in the conference. The unsigned
     * integers less than this number are the valid values of offline_peer_number for
     * the functions querying these peers. Return value is unspecified on failure.
     */
    const uint32_t count(uint32_t conference_number)
        with error for peer_query;

    uint8_t[size] name {

      /**
       * Return the length of the offline peer's name. Return value is unspecified on failure.
       */
      size(uint32_t conference_number, uint32_t offline_peer_number)
          with error for peer_query;

      /**
       * Copy the name of offline_peer_number who is in conference_number to name.
       *
       * Call $size to determine the allocation size for the `name` parameter.
       *
       * @param name A valid memory region large enough to store the peer's name.
       *
       * @return true on success.
       */
      get(uint32_t conference_number, uint32_t offline_peer_number)
          with error for peer_query;
    }

    /**
     * Copy the public key of offline_peer_number who is in conference_number to public_key.
     * public_key must be $PUBLIC_KEY_SIZE long.
     *
     * @return true on success.
     */
    uint8_t[PUBLIC_KEY_SIZE] public_key {
      get(uint32_t conference_number, uint32_t offline_peer_number)
          with error for peer_query;
    }

    /**
     * Return a unix-time timestamp of the last time offline_peer_number was seen to be active.
     */
    uint64_t last_active {
      get(uint32_t conference_number, uint32_t offline_peer_number)
        with error for peer_query;
    }

  }

  /**
   * Set maximum number of offline peers to store, overriding the default.
   */
  bool set_max_offline(uint32_t conference_number, uint32_t max_offline_peers) {
    /**
     * The conference number passed did not designate a valid conference.
     */
    CONFERENCE_NOT_FOUND,
  }


  /**
   * Invites a friend to a conference.
   *
   * @param friend_number The friend number of the friend we want to invite.
   * @param conference_number The conference number of the conference we want to invite the friend to.
   *
   * @return true on success.
   */
  bool invite(uint32_t friend_number, uint32_t conference_number) {
    /**
     * The conference number passed did not designate a valid conference.
     */
    CONFERENCE_NOT_FOUND,
    /**
     * The invite packet failed to send.
     */
    FAIL_SEND,
    /**
     * The client is not connected to the conference.
     */
    NO_CONNECTION,
  }


  /**
   * Joins a conference that the client has been invited to.
   *
   * After successfully joining the conference, the client will not be "connected"
   * to it until a handshaking procedure has been completed. A
   * `${event connected}` event will then occur for the conference. The client
   * will then remain connected to the conference until the conference is deleted,
   * even across core restarts. Many operations on a conference will fail with a
   * corresponding error if attempted on a conference to which the client is not
   * yet connected.
   *
   * @param friend_number The friend number of the friend who sent the invite.
   * @param cookie Received via the `${event invite}` event.
   * @param length The size of cookie.
   *
   * @return conference number on success, an unspecified value on failure.
   */
  uint32_t join(uint32_t friend_number, const uint8_t[length] cookie) {
    /**
     * The cookie passed has an invalid length.
     */
    INVALID_LENGTH,
    /**
     * The conference is not the expected type. This indicates an invalid cookie.
     */
    WRONG_TYPE,
    /**
     * The friend number passed does not designate a valid friend.
     */
    FRIEND_NOT_FOUND,
    /**
     * Client is already in this conference.
     */
    DUPLICATE,
    /**
     * Conference instance failed to initialize.
     */
    INIT_FAIL,
    /**
     * The join packet failed to send.
     */
    FAIL_SEND,
  }


  namespace send {

    /**
     * Send a text chat message to the conference.
     *
     * This function creates a conference message packet and pushes it into the send
     * queue.
     *
     * The message length may not exceed $MAX_MESSAGE_LENGTH. Larger messages
     * must be split by the client and sent as separate messages. Other clients can
     * then reassemble the fragments.
     *
     * @param conference_number The conference number of the conference the message is intended for.
     * @param type Message type (normal, action, ...).
     * @param message A non-NULL pointer to the first element of a byte array
     *   containing the message text.
     * @param length Length of the message to be sent.
     *
     * @return true on success.
     */
    bool message(uint32_t conference_number, MESSAGE_TYPE type, const uint8_t[length] message) {
      /**
       * The conference number passed did not designate a valid conference.
       */
      CONFERENCE_NOT_FOUND,
      /**
       * The message is too long.
       */
      TOO_LONG,
      /**
       * The client is not connected to the conference.
       */
      NO_CONNECTION,
      /**
       * The message packet failed to send.
       */
      FAIL_SEND,
    }
  }

  error for title {
    /**
     * The conference number passed did not designate a valid conference.
     */
    CONFERENCE_NOT_FOUND,
    /**
     * The title is too long or empty.
     */
    INVALID_LENGTH,
    /**
     * The title packet failed to send.
     */
    FAIL_SEND,
  }

  uint8_t[length <= MAX_NAME_LENGTH] title {

    /**
     * Return the length of the conference title. Return value is unspecified on failure.
     *
     * The return value is equal to the `length` argument received by the last
     * `${event title}` callback.
     */
    size(uint32_t conference_number)
        with error for title;

    /**
     * Write the title designated by the given conference number to a byte array.
     *
     * Call $size to determine the allocation size for the `title` parameter.
     *
     * The data written to `title` is equal to the data received by the last
     * `${event title}` callback.
     *
     * @param title A valid memory region large enough to store the title.
     *   If this parameter is NULL, this function has no effect.
     *
     * @return true on success.
     */
    get(uint32_t conference_number)
        with error for title;

    /**
     * Set the conference title and broadcast it to the rest of the conference.
     *
     * Title length cannot be longer than $MAX_NAME_LENGTH.
     *
     * @return true on success.
     */
    set(uint32_t conference_number)
        with error for title;
  }


  uint32_t[size] chatlist {
    /**
     * Return the number of conferences in the Tox instance.
     * This should be used to determine how much memory to allocate for `$get`.
     */
    size();

    /**
     * Copy a list of valid conference numbers into the array chatlist. Determine
     * how much space to allocate for the array with the `$size` function.
     *
     * Note that `${savedata.get}` saves all connected conferences;
     * when toxcore is created from savedata in which conferences were saved, those
     * conferences will be connected at startup, and will be listed by
     * `$get`.
     *
     * The conference number of a loaded conference may differ from the conference
     * number it had when it was saved.
     */
    get();
  }


  /**
   * Returns the type of conference ($TYPE) that conference_number is. Return value is
   * unspecified on failure.
   */
  TYPE type {
    get(uint32_t conference_number) {
      /**
       * The conference number passed did not designate a valid conference.
       */
      CONFERENCE_NOT_FOUND,
    }
  }

  /**
   * Get the conference unique ID.
   *
   * If id is NULL, this function has no effect.
   *
   * @param id A memory region large enough to store $CONFERENCE_ID_SIZE bytes.
   *
   * @return true on success.
   */
  const bool get_id(uint32_t conference_number, uint8_t[CONFERENCE_ID_SIZE] id);

  /**
   * Return the conference number associated with the specified id.
   *
   * @param id A byte array containing the conference id ($CONFERENCE_ID_SIZE).
   *
   * @return the conference number on success, an unspecified value on failure.
   */
  const uint32_t by_id(const uint8_t[CONFERENCE_ID_SIZE] id) {
    NULL,
    /**
     * No conference with the given id exists on the conference list.
     */
    NOT_FOUND,
  }

  /**
   * Get the conference unique ID.
   *
   * If uid is NULL, this function has no effect.
   *
   * @param uid A memory region large enough to store $CONFERENCE_UID_SIZE bytes.
   *
   * @return true on success.
   * @deprecated use $get_id instead (exactly the same function, just renamed).
   */
  const bool get_uid(uint32_t conference_number, uint8_t[CONFERENCE_UID_SIZE] uid);

  /**
   * Return the conference number associated with the specified uid.
   *
   * @param uid A byte array containing the conference id ($CONFERENCE_UID_SIZE).
   *
   * @return the conference number on success, an unspecified value on failure.
   * @deprecated use $by_id instead (exactly the same function, just renamed).
   */
  const uint32_t by_uid(const uint8_t[CONFERENCE_UID_SIZE] uid) {
    NULL,
    /**
     * No conference with the given uid exists on the conference list.
     */
    NOT_FOUND,
  }

}


/*******************************************************************************
 *
 * :: Low-level custom packet sending and receiving
 *
 ******************************************************************************/


namespace friend {

  error for custom_packet {
    NULL,
    /**
     * The friend number did not designate a valid friend.
     */
    FRIEND_NOT_FOUND,
    /**
     * This client is currently not connected to the friend.
     */
    FRIEND_NOT_CONNECTED,
    /**
     * The first byte of data was not in the specified range for the packet type.
     * This range is 192-254 for lossy, and 69, 160-191 for lossless packets.
     */
    INVALID,
    /**
     * Attempted to send an empty packet.
     */
    EMPTY,
    /**
     * Packet data length exceeded $MAX_CUSTOM_PACKET_SIZE.
     */
    TOO_LONG,
    /**
     * Packet queue is full.
     */
    SENDQ,
  }

  namespace send {

    /**
     * Send a custom lossy packet to a friend.
     *
     * The first byte of data must be in the range 192-254. Maximum length of a
     * custom packet is $MAX_CUSTOM_PACKET_SIZE.
     *
     * Lossy packets behave like UDP packets, meaning they might never reach the
     * other side or might arrive more than once (if someone is messing with the
     * connection) or might arrive in the wrong order.
     *
     * Unless latency is an issue, it is recommended that you use lossless custom
     * packets instead.
     *
     * @param friend_number The friend number of the friend this lossy packet
     *   should be sent to.
     * @param data A byte array containing the packet data.
     * @param length The length of the packet data byte array.
     *
     * @return true on success.
     */
    bool lossy_packet(uint32_t friend_number, const uint8_t[length <= MAX_CUSTOM_PACKET_SIZE] data)
        with error for custom_packet;


    /**
     * Send a custom lossless packet to a friend.
     *
     * The first byte of data must be in the range 69, 160-191. Maximum length of a
     * custom packet is $MAX_CUSTOM_PACKET_SIZE.
     *
     * Lossless packet behaviour is comparable to TCP (reliability, arrive in order)
     * but with packets instead of a stream.
     *
     * @param friend_number The friend number of the friend this lossless packet
     *   should be sent to.
     * @param data A byte array containing the packet data.
     * @param length The length of the packet data byte array.
     *
     * @return true on success.
     */
    bool lossless_packet(uint32_t friend_number, const uint8_t[length <= MAX_CUSTOM_PACKET_SIZE] data)
        with error for custom_packet;

  }


  event lossy_packet const {
    /**
     * @param friend_number The friend number of the friend who sent a lossy packet.
     * @param data A byte array containing the received packet data.
     * @param length The length of the packet data byte array.
     */
    typedef void(uint32_t friend_number, const uint8_t[length <= MAX_CUSTOM_PACKET_SIZE] data);
  }


  event lossless_packet const {
    /**
     * @param friend_number The friend number of the friend who sent the packet.
     * @param data A byte array containing the received packet data.
     * @param length The length of the packet data byte array.
     */
    typedef void(uint32_t friend_number, const uint8_t[length <= MAX_CUSTOM_PACKET_SIZE] data);
  }

}



/*******************************************************************************
 *
 * :: Low-level network information
 *
 ******************************************************************************/


error for get_port {
  /**
   * The instance was not bound to any port.
   */
  NOT_BOUND,
}

namespace self {

  uint8_t[PUBLIC_KEY_SIZE] dht_id {
    /**
     * Writes the temporary DHT public key of this instance to a byte array.
     *
     * This can be used in combination with an externally accessible IP address and
     * the bound port (from ${udp_port.get}) to run a temporary bootstrap node.
     *
     * Be aware that every time a new instance is created, the DHT public key
     * changes, meaning this cannot be used to run a permanent bootstrap node.
     *
     * @param dht_id A memory region of at least $PUBLIC_KEY_SIZE bytes. If this
     *   parameter is NULL, this function has no effect.
     */
    get();
  }



  uint16_t udp_port {
    /**
     * Return the UDP port this Tox instance is bound to.
     */
    get() with error for get_port;
  }


  uint16_t tcp_port {
    /**
     * Return the TCP port this Tox instance is bound to. This is only relevant if
     * the instance is acting as a TCP relay.
     */
    get() with error for get_port;
  }

}


/*******************************************************************************
 *
 * :: Group chats
 *
 *****************************************************************************/


/*******************************************************************************
 *
 * :: Group chat numeric constants
 *
 ****************************************************************************/

namespace group {
  /**
   * Maximum length of a group topic.
   */
  const MAX_TOPIC_LENGTH          = 512;

  /**
   * Maximum length of a peer part message.
   */
  const MAX_PART_LENGTH           = 128;

  /**
   * Maximum length of a group name.
   */
  const MAX_GROUP_NAME_LENGTH     = 48;

  /**
   * Maximum length of a group password.
   */
  const MAX_PASSWORD_SIZE         = 32;

  /**
   * Number of bytes in a group Chat ID.
   */
  const CHAT_ID_SIZE              = 32;

  /**
   * Size of a peer public key.
   */
  const PEER_PUBLIC_KEY_SIZE      = 32;

  const MAX_PEER_LENGTH           = 128;
}

/*******************************************************************************
 *
 * :: Group chat state enumerators
 *
 ****************************************************************************/

namespace group {

  enum class PRIVACY_STATE {
    /**
     * The group is considered to be public. Anyone may join the group using the Chat ID.
     *
     * If the group is in this state, even if the Chat ID is never explicitly shared
     * with someone outside of the group, information including the Chat ID, IP addresses,
     * and peer ID's (but not Tox ID's) is visible to anyone with access to a node
     * storing a DHT entry for the given group.
     */
    PUBLIC,

    /**
     * The group is considered to be private. The only way to join the group is by having
     * someone in your contact list send you an invite.
     *
     * If the group is in this state, no group information (mentioned above) is present in the DHT;
     * the DHT is not used for any purpose at all. If a public group is set to private,
     * all DHT information related to the group will expire shortly.
     */
    PRIVATE,
  }

  /**
   * Represents group roles.
   *
   * Roles are are hierarchical in that each role has a set of privileges plus all the privileges
   * of the roles below it.
   */
  enum class ROLE {
    /**
     * May kick all other peers as well as set their role to anything (except founder).
     * Founders may also set the group password, toggle the privacy state, and set the peer limit.
     */
    FOUNDER,

    /**
     * May kick and set the user and observer roles for peers below this role.
     * May also set the group topic.
     */
    MODERATOR,

    /**
     * May communicate with other peers normally.
     */
    USER,

    /**
     * May observe the group and ignore peers; may not communicate with other peers or with the group.
     */
    OBSERVER,
  }

}

/*******************************************************************************
 *
 * :: Group chat instance management
 *
 ******************************************************************************/

namespace group {

  /**
   * Creates a new group chat.
   *
   * This function creates a new group chat object and adds it to the chats array.
   *
   * The client should initiate its peer list with self info after calling this function, as
   * the peer_join callback will not be triggered.
   *
   * @param privacy_state The privacy state of the group. If this is set to TOX_GROUP_PRIVACY_STATE_PUBLIC,
   *   the group will attempt to announce itself to the DHT and anyone with the Chat ID may join.
   *   Otherwise a friend invite will be required to join the group.
   * @param group_name The name of the group. The name must be non-NULL.
   * @param group_name_length The length of the group name. This must be greater than zero and no larger than
   *   $MAX_GROUP_NAME_LENGTH.
   * @param name The name of the peer creating the group.
   * @param name_length The length of the peer's name. This must be greater than zero and no larger
   *   than $MAX_NAME_LENGTH.
   *
   * @return group_number on success, UINT32_MAX on failure.
   */
  uint32_t new(PRIVACY_STATE privacy_state, const uint8_t[group_name_length <= MAX_GROUP_NAME_LENGTH] group_name,
               const uint8_t[name_length <= MAX_NAME_LENGTH] name) {
    /**
     * name exceeds $MAX_NAME_LENGTH or group_name exceeded $MAX_GROUP_NAME_LENGTH.
     */
    TOO_LONG,
    /**
     * name or group_name is NULL or length is zero.
     */
    EMPTY,
    /**
     * $PRIVACY_STATE is an invalid type.
     */
    PRIVACY,
    /**
     * The group instance failed to initialize.
     */
    INIT,
    /**
     * The group state failed to initialize. This usually indicates that something went wrong
     * related to cryptographic signing.
     */
    STATE,
    /**
     * The group failed to announce to the DHT. This indicates a network related error.
     */
    ANNOUNCE,
  }

  /**
   * Joins a group chat with specified Chat ID.
   *
   * This function creates a new group chat object, adds it to the chats array, and sends
   * a DHT announcement to find peers in the group associated with chat_id. Once a peer has been
   * found a join attempt will be initiated.
   *
   * @param chat_id The Chat ID of the group you wish to join. This must be $CHAT_ID_SIZE bytes.
   * @param password The password required to join the group. Set to NULL if no password is required.
   * @param password_length The length of the password. If length is equal to zero,
   *   the password parameter is ignored. length must be no larger than $MAX_PASSWORD_SIZE.
   * @param name The name of the peer joining the group.
   * @param name_length The length of the peer's name. This must be greater than zero and no larger
   *   than $MAX_NAME_LENGTH.
   *
   * @return group_number on success, UINT32_MAX on failure.
   */
  uint32_t join(const uint8_t[CHAT_ID_SIZE] chat_id, const uint8_t[name_length <= MAX_NAME_LENGTH] name,
                const uint8_t[password_length <= MAX_PASSWORD_SIZE] password) {
    /**
     * The group instance failed to initialize.
     */
    INIT,
    /**
     * The chat_id pointer is set to NULL or a group with chat_id already exists. This usually
     * happens if the client attempts to create multiple sessions for the same group.
     */
    BAD_CHAT_ID,
    /**
     * name is NULL or name_length is zero.
     */
    EMPTY,
    /**
     * name exceeds $MAX_NAME_LENGTH.
     */
    TOO_LONG,
    /**
     * Failed to set password. This usually occurs if the password exceeds $MAX_PASSWORD_SIZE.
     */
    PASSWORD,
    /**
     * There was a core error when initiating the group.
     */
    CORE,
  }

  /**
   * Returns true if the group chat is currently connected or attempting to connect to other peers
   * in the group.
   *
   * @param group_number The group number of the designated group.
   */
  bool is_connected(uint32_t group_number) {
    /**
     * The group number passed did not designate a valid group.
     */
    GROUP_NOT_FOUND,
  }

  /**
   * Returns true if the group chat is currently disconnected and not attempting to connect to
   * other peers in the group.
   *
   * @param group_number The group number of the designated group.
   */
  bool disconnect(uint32_t group_number) {
    /**
     * The group number passed did not designate a valid group.
     */
    GROUP_NOT_FOUND,
    /**
     * The group is already disconnected.
     */
    ALREADY_DISCONNECTED,
    /**
     * The group state could not be saved due to a memory allocation error.
     */
    MALLOC,
  }

  /**
   * Reconnects to a group.
   *
   * This function disconnects from all peers in the group, then attempts to reconnect with the group.
   * The caller's state is not changed (i.e. name, status, role, chat public key etc.)
   *
   * @param group_number The group number of the group we wish to reconnect to.
   *
   * @return true on success.
   */
  bool reconnect(uint32_t group_number) {
    /**
     * The group number passed did not designate a valid group.
     */
    GROUP_NOT_FOUND,
    /**
     * There was a core error when initiating the group.
     */
    CORE,
  }

  /**
   * Leaves a group.
   *
   * This function sends a parting packet containing a custom (non-obligatory) message to all
   * peers in a group, and deletes the group from the chat array. All group state information is permanently
   * lost, including keys and role credentials.
   *
   * @param group_number The group number of the group we wish to leave.
   * @param message The parting message to be sent to all the peers. Set to NULL if we do not wish to
   *   send a parting message.
   * @param length The length of the parting message. Set to 0 if we do not wish to send a parting message.
   *
   * @return true if the group chat instance is successfully deleted.
   */
  bool leave(uint32_t group_number, const uint8_t[length <= MAX_PART_LENGTH] message) {
    /**
     * The group number passed did not designate a valid group.
     */
    GROUP_NOT_FOUND,
    /**
     * Message length exceeded $MAX_PART_LENGTH.
     */
    TOO_LONG,
    /**
     * The parting packet failed to send.
     */
    FAIL_SEND,
    /**
     * The group chat instance failed to be deleted. This may occur due to memory related errors.
     */
    DELETE_FAIL,
  }
}

/*******************************************************************************
 *
 * :: Group user-visible client information (nickname/status/role/public key)
 *
 ******************************************************************************/


namespace group {

  inline namespace self {

    /**
     * General error codes for self state get and size functions.
     */
    error for self_query {
      /**
       * The group number passed did not designate a valid group.
       */
      GROUP_NOT_FOUND,
    }

    /**
     * Error codes for self name setting.
     */
    error for self_name_set {
      /**
       * The group number passed did not designate a valid group.
       */
      GROUP_NOT_FOUND,
      /**
       * Name length exceeded $MAX_NAME_LENGTH.
       */
      TOO_LONG,
      /**
       * The length given to the set function is zero or name is a NULL pointer.
       */
      INVALID,
      /**
       * The name is already taken by another peer in the group.
       */
      TAKEN,
      /**
       * The packet failed to send.
       */
      FAIL_SEND,
    }

    uint8_t[length <= MAX_NAME_LENGTH] name {

      /**
       * Set the client's nickname for the group instance designated by the given group number.
       *
       * Nickname length cannot exceed $MAX_NAME_LENGTH. If length is equal to zero or name is a NULL
       * pointer, the function call will fail.
       *
       * @param name A byte array containing the new nickname.
       * @param length The size of the name byte array.
       *
       * @return true on success.
       */
      set(uint32_t group_number) with error for self_name_set;

      /**
       * Return the length of the client's current nickname for the group instance designated
       * by group_number as passed to $set.
       *
       * If no nickname was set before calling this function, the name is empty,
       * and this function returns 0.
       *
       * @see threading for concurrency implications.
       */
      size(uint32_t group_number) with error for self_query;

      /**
       * Write the nickname set by $set to a byte array.
       *
       * If no nickname was set before calling this function, the name is empty,
       * and this function has no effect.
       *
       * Call $size to find out how much memory to allocate for the result.
       *
       * @param name A valid memory location large enough to hold the nickname.
       *   If this parameter is NULL, the function has no effect.
       *
       * @returns true on success.
       */
      get(uint32_t group_number) with error for self_query;
    }

    /**
     * Error codes for self status setting.
     */
    error for self_status_set {
      /**
       * The group number passed did not designate a valid group.
       */
      GROUP_NOT_FOUND,
      /**
       * An invalid type was passed to the set function.
       */
      INVALID,
      /**
       * The packet failed to send.
       */
      FAIL_SEND,
    }

    USER_STATUS status {

      /**
       * Set the client's status for the group instance. Status must be a $USER_STATUS.
       *
       * @return true on success.
       */
      set(uint32_t group_number) with error for self_status_set;

      /**
       * returns the client's status for the group instance on success.
       * return value is unspecified on failure.
       */
      get(uint32_t group_number) with error for self_query;
    }

    ROLE role {

      /**
       * returns the client's role for the group instance on success.
       * return value is unspecified on failure.
       */
      get(uint32_t group_number) with error for self_query;
    }

    uint32_t peer_id {

      /**
       * returns the client's peer id for the group instance on success.
       * return value is unspecified on failure.
       */
       get(uint32_t group_number) with error for self_query;
    }

    uint8_t [length] public_key {

      /**
       * Write the client's group public key designated by the given group number to a byte array.
       *
       * This key will be parmanently tied to the client's identity for this particular group until
       * the client explicitly leaves the group or gets kicked. This key is the only way for
       * other peers to reliably identify the client across client restarts.
       *
       * `public_key` should have room for at least $PEER_PUBLIC_KEY_SIZE bytes.
       *
       * @param public_key A valid memory region large enough to store the public key.
       *   If this parameter is NULL, this function call has no effect.
       *
       * @return true on success.
       */
      get(uint32_t group_number) with error for self_query;
    }
  }

}

/*******************************************************************************
 *
 * :: Peer-specific group state queries.
 *
 ******************************************************************************/

namespace group {

  namespace peer {

    /**
     * Error codes for peer info queries.
     */
    error for query {
      /**
       * The group number passed did not designate a valid group.
       */
      GROUP_NOT_FOUND,
      /**
       * The ID passed did not designate a valid peer.
       */
      PEER_NOT_FOUND,
    }

    uint8_t[length <= MAX_NAME_LENGTH] name {

      /**
       * Return the length of the peer's name. If the group number or ID is invalid, the
       * return value is unspecified.
       *
       * The return value is equal to the `length` argument received by the last
       * `${event name}` callback.
       */
      size(uint32_t group_number, uint32_t peer_id) with error for query;

      /**
       * Write the name of the peer designated by the given ID to a byte
       * array.
       *
       * Call $size to determine the allocation size for the `name` parameter.
       *
       * The data written to `name` is equal to the data received by the last
       * `${event name}` callback.
       *
       * @param group_number The group number of the group we wish to query.
       * @param peer_id The ID of the peer whose name we want to retrieve.
       * @param name A valid memory region large enough to store the friend's name.
       *
       * @return true on success.
       */
      get(uint32_t group_number, uint32_t  peer_id) with error for query;
    }

    USER_STATUS status {

      /**
       * Return the peer's user status (away/busy/...). If the ID or group number is
       * invalid, the return value is unspecified.
       *
       * The status returned is equal to the last status received through the
       * `${event status}` callback.
       */
      get(uint32_t group_number, uint32_t peer_id) with error for query;
    }

    ROLE role {
      /**
       * Return the peer's role (user/moderator/founder...). If the ID or group number is
       * invalid, the return value is unspecified.
       *
       * The role returned is equal to the last role received through the
       * `${event moderation}` callback.
       */
      get(uint32_t group_number, uint32_t peer_id) with error for query;
    }

    uint8_t[length] public_key {

      /**
       * Write the group public key with the designated peer_id for the designated group number to public_key.
       *
       * This key will be parmanently tied to a particular peer until they explicitly leave the group or
       * get kicked, and is the only way to reliably identify the same peer across client restarts.
       *
       * `public_key` should have room for at least $PEER_PUBLIC_KEY_SIZE bytes.
       *
       * @param public_key A valid memory region large enough to store the public key.
       *   If this parameter is NULL, this function call has no effect.
       *
       * @return true on success.
       */
       get(uint32_t group_number, uint32_t peer_id) with error for query;
    }

    /**
     * This event is triggered when a peer changes their nickname.
     */
    event name const {
      /**
       * @param group_number The group number of the group the name change is intended for.
       * @param peer_id The ID of the peer who has changed their name.
       * @param name The name data.
       * @param length The length of the name.
       */
      typedef void(uint32_t group_number, uint32_t peer_id, const uint8_t[length <= MAX_NAME_LENGTH] name);
    }

    /**
     * This event is triggered when a peer changes their status.
     */
    event status const {
      /**
       * @param group_number The group number of the group the status change is intended for.
       * @param peer_id The ID of the peer who has changed their status.
       * @param status The new status of the peer.
       */
      typedef void(uint32_t group_number, uint32_t peer_id, USER_STATUS status);
    }
  }

}


/******************************************************************************
 *
 * :: Group chat state queries and events.
 *
 ******************************************************************************/

namespace group {

  /**
   * General error codes for group state get and size functions.
   */
  error for state_queries {
      /**
       * The group number passed did not designate a valid group.
       */
      GROUP_NOT_FOUND,
  }

  /**
   * Error codes for group topic setting.
   */
  error for topic_set {
      /**
       * The group number passed did not designate a valid group.
       */
      GROUP_NOT_FOUND,
      /**
       * Topic length exceeded $MAX_TOPIC_LENGTH.
       */
      TOO_LONG,
      /**
       * The caller does not have the required permissions to set the topic.
       */
      PERMISSIONS,
      /**
       * The packet could not be created. This error is usually related to cryptographic signing.
       */
      FAIL_CREATE,
      /**
       * The packet failed to send.
       */
      FAIL_SEND,
      /**
       * The group is disconnected.
       */
      DISCONNECTED,
  }

  uint8_t[length <= MAX_TOPIC_LENGTH] topic {

    /**
     * Set the group topic and broadcast it to the rest of the group.
     *
     * topic length cannot be longer than $MAX_TOPIC_LENGTH. If length is equal to zero or
     * topic is set to NULL, the topic will be unset.
     *
     * @returns true on success.
     */
    set(uint32_t group_number) with error for topic_set;

    /**
     * Return the length of the group topic. If the group number is invalid, the
     * return value is unspecified.
     *
     * The return value is equal to the `length` argument received by the last
     * `${event topic}` callback.
     */
    size(uint32_t group_number) with error for state_queries;

    /**
     * Write the topic designated by the given group number to a byte array.
     *
     * Call $size to determine the allocation size for the `topic` parameter.
     *
     * The data written to `topic` is equal to the data received by the last
     * `${event topic}` callback.
     *
     * @param topic A valid memory region large enough to store the topic.
     *   If this parameter is NULL, this function has no effect.
     *
     * @return true on success.
     */
    get(uint32_t group_number) with error for state_queries;
  }

  /**
   * This event is triggered when a peer changes the group topic.
   */
  event topic const {
    /**
     * @param group_number The group number of the group the topic change is intended for.
     * @param peer_id The ID of the peer who changed the topic. If the peer who set the topic
     *   is not present in our peer list this value will be set to 0.
     * @param topic The topic data.
     * @param length The topic length.
     */
    typedef void(uint32_t group_number, uint32_t peer_id, const uint8_t[length <= MAX_TOPIC_LENGTH] topic);
  }

  uint8_t[length <= MAX_TOPIC_LENGTH] name {
    /**
     * Return the length of the group name. If the group number is invalid, the
     * return value is unspecified.
     */
    size(uint32_t group_number) with error for state_queries;

    /**
     * Write the name of the group designated by the given group number to a byte array.
     *
     * Call $size to determine the allocation size for the `name` parameter.
     *
     * @param name A valid memory region large enough to store the group name.
     *   If this parameter is NULL, this function call has no effect.
     *
     * @return true on success.
     */
    get(uint32_t group_number) with error for state_queries;
  }

  uint8_t[length] chat_id {

    /**
     * Write the Chat ID designated by the given group number to a byte array.
     *
     * `chat_id` should have room for at least $CHAT_ID_SIZE bytes.
     *
     * @param chat_id A valid memory region large enough to store the Chat ID.
     *   If this parameter is NULL, this function call has no effect.
     *
     * @return true on success.
     */
    get(uint32_t group_number) with error for state_queries;
  }

  uint32_t number_groups {
    /**
     * Return the number of groups in the Tox chats array.
     */
     get();
  }

  PRIVACY_STATE privacy_state {

    /**
     * Return the privacy state of the group designated by the given group number. If group number
     * is invalid, the return value is unspecified.
     *
     * The value returned is equal to the data received by the last
     * `${event privacy_state}` callback.
     *
     * @see the `Group chat founder controls` section for the respective set function.
     */
    get(uint32_t group_number) with error for state_queries;
  }

  /**
   * This event is triggered when the group founder changes the privacy state.
   */
  event privacy_state const {
    /**
     * @param group_number The group number of the group the topic change is intended for.
     * @param privacy_state The new privacy state.
     */
    typedef void(uint32_t group_number, PRIVACY_STATE privacy_state);
  }

  uint32_t peer_limit {

    /**
     * Return the maximum number of peers allowed for the group designated by the given group number.
     * If the group number is invalid, the return value is unspecified.
     *
     * The value returned is equal to the data received by the last
     * `${event peer_limit}` callback.
     *
     * @see the `Group chat founder controls` section for the respective set function.
     */
    get(uint32_t group_number) with error for state_queries;
  }

  /**
   * This event is triggered when the group founder changes the maximum peer limit.
   */
  event peer_limit const {
    /**
     * @param group_number The group number of the group for which the peer limit has changed.
     * @param peer_limit The new peer limit for the group.
     */
    typedef void(uint32_t group_number, uint32_t peer_limit);
  }

  uint8_t[length <= MAX_PASSWORD_SIZE] password {

    /**
     * Return the length of the group password. If the group number is invalid, the
     * return value is unspecified.
     */
    size(uint32_t group_number) with error for state_queries;

    /**
     * Write the password for the group designated by the given group number to a byte array.
     *
     * Call $size to determine the allocation size for the `password` parameter.
     *
     * The data received is equal to the data received by the last
     * `${event password}` callback.
     *
     * @see the `Group chat founder controls` section for the respective set function.
     *
     * @param password A valid memory region large enough to store the group password.
     *   If this parameter is NULL, this function call has no effect.
     *
     * @return true on success.
     */
    get(uint32_t group_number) with error for state_queries;
  }

  /**
   * This event is triggered when the group founder changes the group password.
   */
  event password const {
    /**
     * @param group_number The group number of the group for which the password has changed.
     * @param password The new group password.
     * @param length The length of the password.
     */
    typedef void(uint32_t group_number, const uint8_t[length <= MAX_PASSWORD_SIZE] password);
  }

}

/******************************************************************************
 *
 * :: Group chat message sending
 *
 ******************************************************************************/

namespace group {

  namespace send {
    /**
     * Send a text chat message to the group.
     *
     * This function creates a group message packet and pushes it into the send
     * queue.
     *
     * The message length may not exceed $MAX_MESSAGE_LENGTH. Larger messages
     * must be split by the client and sent as separate messages. Other clients can
     * then reassemble the fragments. Messages may not be empty.
     *
     * @param group_number The group number of the group the message is intended for.
     * @param type Message type (normal, action, ...).
     * @param message A non-NULL pointer to the first element of a byte array
     *   containing the message text.
     * @param length Length of the message to be sent.
     *
     * @return true on success.
     */
    bool message(uint32_t group_number, MESSAGE_TYPE type, const uint8_t[length <= MAX_MESSAGE_LENGTH] message) {
      /**
       * The group number passed did not designate a valid group.
       */
      GROUP_NOT_FOUND,
      /**
       * Message length exceeded $MAX_MESSAGE_LENGTH.
       */
      TOO_LONG,
      /**
       * The message pointer is null or length is zero.
       */
      EMPTY,
      /**
       * The message type is invalid.
       */
      BAD_TYPE,
      /**
       * The caller does not have the required permissions to send group messages.
       */
      PERMISSIONS,
      /**
       * Packet failed to send.
       */
      FAIL_SEND,
      /**
       * The group is disconnected.
       */
      DISCONNECTED,
    }

    /**
     * Send a text chat message to the specified peer in the specified group.
     *
     * This function creates a group private message packet and pushes it into the send
     * queue.
     *
     * The message length may not exceed $MAX_MESSAGE_LENGTH. Larger messages
     * must be split by the client and sent as separate messages. Other clients can
     * then reassemble the fragments. Messages may not be empty.
     *
     * @param group_number The group number of the group the message is intended for.
     * @param peer_id The ID of the peer the message is intended for.
     * @param message A non-NULL pointer to the first element of a byte array
     *   containing the message text.
     * @param length Length of the message to be sent.
     *
     * @return true on success.
     */
    bool private_message(uint32_t group_number, uint32_t peer_id, MESSAGE_TYPE type, const uint8_t[length <= MAX_MESSAGE_LENGTH] message) {
      /**
       * The group number passed did not designate a valid group.
       */
      GROUP_NOT_FOUND,
      /**
       * The ID passed did not designate a valid peer.
       */
      PEER_NOT_FOUND,
      /**
       * Message length exceeded $MAX_MESSAGE_LENGTH.
       */
      TOO_LONG,
      /**
       * The message pointer is null or length is zero.
       */
      EMPTY,
      /**
       * The caller does not have the required permissions to send group messages.
       */
      PERMISSIONS,
      /**
       * Packet failed to send.
       */
      FAIL_SEND,
      /**
       * The group is disconnected.
       */
      DISCONNECTED,
      /**
       * The message type is invalid.
       */
      BAD_TYPE,
    }

    /**
     * Send a custom packet to the group.
     *
     * If lossless is true the packet will be lossless. Lossless packet behaviour is comparable
     * to TCP (reliability, arrive in order) but with packets instead of a stream.
     *
     * If lossless is false, the packet will be lossy. Lossy packets behave like UDP packets,
     * meaning they might never reach the other side or might arrive more than once (if someone
     * is messing with the connection) or might arrive in the wrong order.
     *
     * Unless latency is an issue or message reliability is not important, it is recommended that you use
     * lossless custom packets.
     *
     * @param group_number The group number of the group the message is intended for.
     * @param lossless True if the packet should be lossless.
     * @param data A byte array containing the packet data.
     * @param length The length of the packet data byte array.
     *
     * @return true on success.
     */
    bool custom_packet(uint32_t group_number, bool lossless, const uint8_t[length <= MAX_MESSAGE_LENGTH] data) {
      /**
       * The group number passed did not designate a valid group.
       */
      GROUP_NOT_FOUND,
      /**
       * Message length exceeded $MAX_MESSAGE_LENGTH.
       */
      TOO_LONG,
      /**
       * The message pointer is null or length is zero.
       */
      EMPTY,
      /**
       * The caller does not have the required permissions to send group messages.
       */
      PERMISSIONS,
      /**
       * The group is disconnected.
       */
      DISCONNECTED,
    }
  }
}

/******************************************************************************
 *
 * :: Group chat message receiving
 *
 ******************************************************************************/

namespace group {

  /**
   * This event is triggered when the client receives a group message.
   */
  event message const {
    /**
     * @param group_number The group number of the group the message is intended for.
     * @param peer_id The ID of the peer who sent the message.
     * @param type The type of message (normal, action, ...).
     * @param message The message data.
     * @param length The length of the message.
     */
    typedef void(uint32_t group_number, uint32_t peer_id, MESSAGE_TYPE type, const uint8_t[length <= MAX_MESSAGE_LENGTH] message);
  }

  /**
   * This event is triggered when the client receives a private message.
   */
  event private_message const {
    /**
     * @param group_number The group number of the group the private message is intended for.
     * @param peer_id The ID of the peer who sent the private message.
     * @param message The message data.
     * @param length The length of the message.
     */
    typedef void(uint32_t group_number, uint32_t peer_id, MESSAGE_TYPE type, const uint8_t[length <= MAX_MESSAGE_LENGTH] message);
  }

  /**
   * This event is triggered when the client receives a custom packet.
   */
  event custom_packet const {
    /**
     * @param group_number The group number of the group the custom packet is intended for.
     * @param peer_id The ID of the peer who sent the custom packet.
     * @param data The custom packet data.
     * @param length The length of the data.
     */
    typedef void(uint32_t group_number, uint32_t peer_id, const uint8_t[length <= MAX_MESSAGE_LENGTH] data);
  }

}

/******************************************************************************
 *
 * :: Group chat inviting and join/part events
 *
 ******************************************************************************/

namespace group {

  namespace invite {

    /**
     * Invite a friend to a group.
     *
     * This function creates an invite request packet and pushes it to the send queue.
     *
     * @param group_number The group number of the group the message is intended for.
     * @param friend_number The friend number of the friend the invite is intended for.
     *
     * @return true on success.
     */
    bool friend(uint32_t group_number, uint32_t friend_number) {
      /**
       * The group number passed did not designate a valid group.
       */
      GROUP_NOT_FOUND,
      /**
       * The friend number passed did not designate a valid friend.
       */
      FRIEND_NOT_FOUND,
      /**
       * Creation of the invite packet failed. This indicates a network related error.
       */
      INVITE_FAIL,
      /**
       * Packet failed to send.
       */
      FAIL_SEND,
      /**
       * The group is disconnected.
       */
      DISCONNECTED,
    }

    /**
     * Accept an invite to a group chat that the client previously received from a friend. The invite
     * is only valid while the inviter is present in the group.
     *
     * @param invite_data The invite data received from the `${event invite}` event.
     * @param length The length of the invite data.
     * @param name The name of the peer joining the group.
     * @param name_length The length of the peer's name. This must be greater than zero and no larger
     *   than $MAX_NAME_LENGTH.
     * @param password The password required to join the group. Set to NULL if no password is required.
     * @param password_length The length of the password. If password_length is equal to zero, the password
     *    parameter will be ignored. password_length must be no larger than $MAX_PASSWORD_SIZE.
     *
     * @return the group_number on success, UINT32_MAX on failure.
     */
    uint32_t accept(uint32_t friend_number, const uint8_t[length] invite_data,
                    const uint8_t[name_length <= MAX_NAME_LENGTH] name,
                    const uint8_t[password_length <= MAX_PASSWORD_SIZE] password) {
      /**
       * The invite data is not in the expected format.
       */
      BAD_INVITE,
      /**
       * The group instance failed to initialize.
       */
      INIT_FAILED,
      /**
       * name exceeds $MAX_NAME_LENGTH
       */
      TOO_LONG,
      /**
       * name is NULL or name_length is zero.
       */
      EMPTY,
      /**
       * Failed to set password. This usually occurs if the password exceeds $MAX_PASSWORD_SIZE.
       */
      PASSWORD,
      /**
       * There was a core error when initiating the group.
       */
      CORE,
      /**
       * Packet failed to send.
       */
      FAIL_SEND,
    }
  }

  /**
   * This event is triggered when the client receives a group invite from a friend. The client must store
   * invite_data which is used to join the group via tox_group_invite_accept.
   */
  event invite const {
    /**
     * @param friend_number The friend number of the contact who sent the invite.
     * @param invite_data The invite data.
     * @param length The length of invite_data.
     */
    typedef void(uint32_t friend_number, const uint8_t[length] invite_data, const uint8_t[group_name_length] group_name);
  }

  /**
   * This event is triggered when a peer other than self joins the group.
   */
  event peer_join const {
    /**
     * @param group_number The group number of the group in which a new peer has joined.
     * @param peer_id The permanent ID of the new peer. This id should not be relied on for
     * client behaviour and should be treated as a random value.
     */
    typedef void(uint32_t group_number, uint32_t peer_id);
  }

  /**
   * Represents peer exit events. These should be used with the `${event peer_exit}` event.
   */
  enum class EXIT_TYPE {
    /**
     * The peer has quit the group.
     */
    QUIT,

    /**
     * Your connection with this peer has timed out.
     */
    TIMEOUT,

    /**
     * Your connection with this peer has been severed.
     */
    DISCONNECTED,

    /**
     * Your connection with all peers has been severed. This will occur when you are kicked from
     * a group, rejoin a group, or manually disconnect from a group.
     */
    SELF_DISCONNECTED,

    /**
     * The peer has been kicked.
     */
    KICK,

    /**
     * The peer provided invalid group sync information.
     */
    SYNC_ERROR,
  }

  /**
   * This event is triggered when a peer other than self exits the group.
   */
  event peer_exit const {
    /**
     * @param group_number The group number of the group in which a peer has left.
     * @param peer_id The ID of the peer who left the group. This ID no longer designates a valid peer
     *     and cannot be used for API calls.
     * @param exit_type The type of exit event. One of ${EXIT_TYPE}.
     * @param name The nickname of the peer who left the group.
     * @param part_message The parting message data.
     * @param length The length of the parting message.
     */
    typedef void(uint32_t group_number, uint32_t peer_id, EXIT_TYPE exit_type, const uint8_t[name_length <= MAX_NAME_LENGTH] name,
                 const uint8_t[length <= MAX_PART_LENGTH] part_message);
  }

  /**
   * This event is triggered when the client has successfully joined a group. Use this to initialize
   * any group information the client may need.
   */
  event self_join const {
    /**
     * @param group_number The group number of the group that the client has joined.
     */
    typedef void(uint32_t group_number);
  }

  /**
   * Represents types of failed group join attempts. These are used in the tox_callback_group_rejected
   * callback when a peer fails to join a group.
   */
  enum class JOIN_FAIL {
    /**
     * You are using the same nickname as someone who is already in the group.
     */
    NAME_TAKEN,

    /**
     * The group peer limit has been reached.
     */
    PEER_LIMIT,

    /**
     * You have supplied an invalid password.
     */
    INVALID_PASSWORD,

    /**
     * The join attempt failed due to an unspecified error. This often occurs when the group is
     * not found in the DHT.
     */
    UNKNOWN,
  }

  /**
   * This event is triggered when the client fails to join a group.
   */
  event join_fail const {
    /**
     * @param group_number The group number of the group for which the join has failed.
     * @param fail_type The type of group rejection.
     */
    typedef void(uint32_t group_number, JOIN_FAIL fail_type);
  }
}


/*******************************************************************************
 *
 * :: Group chat founder controls (these only work for the group founder)
 *
 ******************************************************************************/

namespace group {

  namespace founder {

    /**
     * Set or unset the group password.
     *
     * This function sets the groups password, creates a new group shared state including the change,
     * and distributes it to the rest of the group.
     *
     * @param group_number The group number of the group for which we wish to set the password.
     * @param password The password we want to set. Set password to NULL to unset the password.
     * @param length The length of the password. length must be no longer than $MAX_PASSWORD_SIZE.
     *
     * @return true on success.
     */
    bool set_password(uint32_t group_number, const uint8_t[length <= MAX_PASSWORD_SIZE] password) {
      /**
       * The group number passed did not designate a valid group.
       */
      GROUP_NOT_FOUND,
      /**
       * The caller does not have the required permissions to set the password.
       */
      PERMISSIONS,
      /**
       * Password length exceeded $MAX_PASSWORD_SIZE.
       */
      TOO_LONG,
      /**
       * The packet failed to send.
       */
      FAIL_SEND,
      /**
       * The function failed to allocate enough memory for the operation.
       */
      MALLOC,
      /**
       * The group is disconnected.
       */
      DISCONNECTED,
    }

    /**
     * Set the group privacy state.
     *
     * This function sets the group's privacy state, creates a new group shared state
     * including the change, and distributes it to the rest of the group.
     *
     * If an attempt is made to set the privacy state to the same state that the group is already
     * in, the function call will be successful and no action will be taken.
     *
     * @param group_number The group number of the group for which we wish to change the privacy state.
     * @param privacy_state The privacy state we wish to set the group to.
     *
     * @return true on success.
     */
    bool set_privacy_state(uint32_t group_number, PRIVACY_STATE privacy_state) {
      /**
       * The group number passed did not designate a valid group.
       */
      GROUP_NOT_FOUND,
      /**
       * $PRIVACY_STATE is an invalid type.
       */
      INVALID,
      /**
       * The caller does not have the required permissions to set the privacy state.
       */
      PERMISSIONS,
      /**
       * The privacy state could not be set. This may occur due to an error related to
       * cryptographic signing of the new shared state.
       */
      FAIL_SET,
      /**
       * The packet failed to send.
       */
      FAIL_SEND,
      /**
       * The group is disconnected.
       */
      DISCONNECTED,
    }

    /**
     * Set the group peer limit.
     *
     * This function sets a limit for the number of peers who may be in the group, creates a new
     * group shared state including the change, and distributes it to the rest of the group.
     *
     * @param group_number The group number of the group for which we wish to set the peer limit.
     * @param max_peers The maximum number of peers to allow in the group.
     *
     * @return true on success.
     */
    bool set_peer_limit(uint32_t group_number, uint32_t max_peers) {
      /**
       * The group number passed did not designate a valid group.
       */
      GROUP_NOT_FOUND,
      /**
       * The caller does not have the required permissions to set the peer limit.
       */
      PERMISSIONS,
      /**
       * The peer limit could not be set. This may occur due to an error related to
       * cryptographic signing of the new shared state.
       */
      FAIL_SET,
      /**
       * The packet failed to send.
       */
      FAIL_SEND,
      /**
       * The group is disconnected.
       */
      DISCONNECTED,
    }
  }

}

/*******************************************************************************
 *
 * :: Group chat moderation
 *
 ******************************************************************************/

namespace group {

  /**
   * Ignore or unignore a peer.
   *
   * @param group_number The group number of the group the in which you wish to ignore a peer.
   * @param peer_id The ID of the peer who shall be ignored or unignored.
   * @param ignore True to ignore the peer, false to unignore the peer.
   *
   * @return true on success.
   */
  bool toggle_ignore(uint32_t group_number, uint32_t peer_id, bool ignore) {
      /**
       * The group number passed did not designate a valid group.
       */
      GROUP_NOT_FOUND,
      /**
       * The ID passed did not designate a valid peer.
       */
      PEER_NOT_FOUND,
      /**
       * The caller attempted to ignore himself.
       */
      SELF,
  }

  namespace mod {

    /**
     * Set a peer's role.
     *
     * This function will first remove the peer's previous role and then assign them a new role.
     * It will also send a packet to the rest of the group, requesting that they perform
     * the role reassignment. Note: peers cannot be set to the founder role.
     *
     * @param group_number The group number of the group the in which you wish set the peer's role.
     * @param peer_id The ID of the peer whose role you wish to set.
     * @param role The role you wish to set the peer to.
     *
     * @return true on success.
     */
    bool set_role(uint32_t group_number, uint32_t peer_id, ROLE role) {
      /**
       * The group number passed did not designate a valid group.
       */
      GROUP_NOT_FOUND,
      /**
       * The ID passed did not designate a valid peer. Note: you cannot set your own role.
       */
      PEER_NOT_FOUND,
      /**
       * The caller does not have the required permissions for this action.
       */
      PERMISSIONS,
      /**
       * The role assignment is invalid. This will occur if you try to set a peer's role to
       * the role they already have.
       */
      ASSIGNMENT,
      /**
       * The role was not successfully set. This may occur if the packet failed to send, or
       * if the role limit has been reached.
       */
      FAIL_ACTION,
      /**
       * The caller attempted to set their own role.
       */
      SELF,
    }

    /**
     * Kick a peer.
     *
     * This function will remove a peer from the caller's peer list and send a packet to all
     * group members requesting them to do the same. Note: This function will not trigger
     * the `${event peer_exit}` event for the caller.
     *
     * @param group_number The group number of the group the action is intended for.
     * @param peer_id The ID of the peer who will be kicked.
     *
     * @return true on success.
     */
    bool kick_peer(uint32_t group_number, uint32_t peer_id) {
      /**
       * The group number passed did not designate a valid group.
       */
      GROUP_NOT_FOUND,
      /**
       * The ID passed did not designate a valid peer.
       */
      PEER_NOT_FOUND,
      /**
       * The caller does not have the required permissions for this action.
       */
      PERMISSIONS,
      /**
       * The peer could not be kicked from the group.
       */
      FAIL_ACTION,
      /**
       * The packet failed to send.
       */
      FAIL_SEND,
      /**
       * The caller attempted to set their own role.
       */
      SELF,
    }
  }


  /**
   * Represents moderation events. These should be used with the `${event moderation}` event.
   */
  enum class MOD_EVENT {
    /**
     * A peer has been kicked from the group.
     */
    KICK,

    /**
     * A peer as been given the observer role.
     */
    OBSERVER,

    /**
     * A peer has been given the user role.
     */
    USER,

    /**
     * A peer has been given the moderator role.
     */
    MODERATOR,
  }

  /**
   * This event is triggered when a moderator or founder executes a moderation event, with the exception
   * of the peer who initiates the event.
   */
  event moderation const {
    /**
     * @param group_number The group number of the group the event is intended for.
     * @param source_peer_number The ID of the peer who initiated the event.
     * @param target_peer_number The ID of the peer who is the target of the event.
     * @param mod_type The type of event.
     */
    typedef void(uint32_t group_number, uint32_t source_peer_number, uint32_t target_peer_number, MOD_EVENT mod_type);
  }
}

} // class tox

%{
#ifdef __cplusplus
}
#endif

typedef TOX_ERR_OPTIONS_NEW Tox_Err_Options_New;
typedef TOX_ERR_NEW Tox_Err_New;
typedef TOX_ERR_BOOTSTRAP Tox_Err_Bootstrap;
typedef TOX_ERR_SET_INFO Tox_Err_Set_Info;
typedef TOX_ERR_FRIEND_ADD Tox_Err_Friend_Add;
typedef TOX_ERR_FRIEND_DELETE Tox_Err_Friend_Delete;
typedef TOX_ERR_FRIEND_BY_PUBLIC_KEY Tox_Err_Friend_By_Public_Key;
typedef TOX_ERR_FRIEND_GET_PUBLIC_KEY Tox_Err_Friend_Get_Public_Key;
typedef TOX_ERR_FRIEND_GET_LAST_ONLINE Tox_Err_Friend_Get_Last_Online;
typedef TOX_ERR_FRIEND_QUERY Tox_Err_Friend_Query;
typedef TOX_ERR_SET_TYPING Tox_Err_Set_Typing;
typedef TOX_ERR_FRIEND_SEND_MESSAGE Tox_Err_Friend_Send_Message;
typedef TOX_ERR_FILE_CONTROL Tox_Err_File_Control;
typedef TOX_ERR_FILE_SEEK Tox_Err_File_Seek;
typedef TOX_ERR_FILE_GET Tox_Err_File_Get;
typedef TOX_ERR_FILE_SEND Tox_Err_File_Send;
typedef TOX_ERR_FILE_SEND_CHUNK Tox_Err_File_Send_Chunk;
typedef TOX_ERR_CONFERENCE_NEW Tox_Err_Conference_New;
typedef TOX_ERR_CONFERENCE_DELETE Tox_Err_Conference_Delete;
typedef TOX_ERR_CONFERENCE_PEER_QUERY Tox_Err_Conference_Peer_Query;
typedef TOX_ERR_CONFERENCE_SET_MAX_OFFLINE Tox_Err_Conference_Set_Max_Offline;
typedef TOX_ERR_CONFERENCE_BY_ID Tox_Err_Conference_By_Id;
typedef TOX_ERR_CONFERENCE_BY_UID Tox_Err_Conference_By_Uid;
typedef TOX_ERR_CONFERENCE_INVITE Tox_Err_Conference_Invite;
typedef TOX_ERR_CONFERENCE_JOIN Tox_Err_Conference_Join;
typedef TOX_ERR_CONFERENCE_SEND_MESSAGE Tox_Err_Conference_Send_Message;
typedef TOX_ERR_CONFERENCE_TITLE Tox_Err_Conference_Title;
typedef TOX_ERR_CONFERENCE_GET_TYPE Tox_Err_Conference_Get_Type;
typedef TOX_ERR_FRIEND_CUSTOM_PACKET Tox_Err_Friend_Custom_Packet;
typedef TOX_ERR_GET_PORT Tox_Err_Get_Port;
typedef TOX_ERR_GROUP_NEW Tox_Err_Group_New;
typedef TOX_ERR_GROUP_JOIN Tox_Err_Group_Join;
typedef TOX_ERR_GROUP_RECONNECT Tox_Err_Group_Reconnect;
typedef TOX_ERR_GROUP_LEAVE Tox_Err_Group_Leave;
typedef TOX_ERR_GROUP_SELF_QUERY Tox_Err_Group_Self_Query;
typedef TOX_ERR_GROUP_SELF_NAME_SET Tox_Err_Group_Self_Name_Set;
typedef TOX_ERR_GROUP_SELF_STATUS_SET Tox_Err_Group_Self_Status_Set;
typedef TOX_ERR_GROUP_PEER_QUERY Tox_Err_Group_Peer_Query;
typedef TOX_ERR_GROUP_STATE_QUERIES Tox_Err_Group_State_Queries;
typedef TOX_ERR_GROUP_TOPIC_SET Tox_Err_Group_Topic_Set;
typedef TOX_ERR_GROUP_SEND_MESSAGE Tox_Err_Group_Send_Message;
typedef TOX_ERR_GROUP_SEND_PRIVATE_MESSAGE Tox_Err_Group_Send_Private_Message;
typedef TOX_ERR_GROUP_SEND_CUSTOM_PACKET Tox_Err_Group_Send_Custom_Packet;
typedef TOX_ERR_GROUP_INVITE_FRIEND Tox_Err_Group_Invite_Friend;
typedef TOX_ERR_GROUP_INVITE_ACCEPT Tox_Err_Group_Invite_Accept;
typedef TOX_ERR_GROUP_FOUNDER_SET_PASSWORD Tox_Err_Group_Founder_Set_Password;
typedef TOX_ERR_GROUP_FOUNDER_SET_PRIVACY_STATE Tox_Err_Group_Founder_Set_Privacy_State;
typedef TOX_ERR_GROUP_FOUNDER_SET_PEER_LIMIT Tox_Err_Group_Founder_Set_Peer_Limit;
typedef TOX_ERR_GROUP_TOGGLE_IGNORE Tox_Err_Group_Toggle_Ignore;
typedef TOX_ERR_GROUP_MOD_SET_ROLE Tox_Err_Group_Mod_Set_Role;
typedef TOX_ERR_GROUP_MOD_KICK_PEER Tox_Err_Group_Mod_Kick_Peer;
typedef TOX_ERR_GROUP_DISCONNECT Tox_Err_Group_Disconnect;
typedef TOX_ERR_GROUP_IS_CONNECTED Tox_Err_Group_Is_Connected;
typedef TOX_USER_STATUS Tox_User_Status;
typedef TOX_MESSAGE_TYPE Tox_Message_Type;
typedef TOX_PROXY_TYPE Tox_Proxy_Type;
typedef TOX_SAVEDATA_TYPE Tox_Savedata_Type;
typedef TOX_LOG_LEVEL Tox_Log_Level;
typedef TOX_CONNECTION Tox_Connection;
typedef TOX_FILE_CONTROL Tox_File_Control;
typedef TOX_CONFERENCE_TYPE Tox_Conference_Type;
typedef TOX_GROUP_JOIN_FAIL Tox_Group_Join_Fail;
typedef TOX_GROUP_PRIVACY_STATE Tox_Group_Privacy_State;
typedef TOX_GROUP_MOD_EVENT Tox_Group_Mod_Event;
typedef TOX_GROUP_ROLE Tox_Group_Role;
typedef TOX_GROUP_EXIT_TYPE Tox_Group_Exit_Type;

//!TOKSTYLE+

#endif // C_TOXCORE_TOXCORE_TOX_H
%}
