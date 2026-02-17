/**
 * Typed EventEmitter implementation
 * Replaces Node.js EventEmitter with a lightweight typed alternative
 */

// deno-lint-ignore no-explicit-any
type EventListener = (...args: any[]) => void;

interface ListenerEntry {
  listener: EventListener;
  once: boolean;
}

/**
 * A typed EventEmitter that provides type-safe event handling.
 *
 * Usage:
 * ```ts
 * interface MyEvents {
 *   data: [Uint8Array];
 *   error: [Error];
 *   close: [];
 * }
 *
 * class MyClass extends EventEmitter<MyEvents> {}
 * ```
 */
// deno-lint-ignore no-explicit-any
export class EventEmitter<
  EventMap extends { [K in keyof EventMap]: unknown[] } = Record<string, any[]>,
> {
  private _events: Map<keyof EventMap, ListenerEntry[]> = new Map();
  private _maxListeners: number = 10;

  /**
   * Add a listener for the given event
   */
  on<K extends keyof EventMap>(event: K, listener: (...args: EventMap[K]) => void): this {
    return this.addListener(event, listener);
  }

  /**
   * Add a listener for the given event (alias for on)
   */
  addListener<K extends keyof EventMap>(event: K, listener: (...args: EventMap[K]) => void): this {
    const listeners = this._events.get(event) ?? [];
    listeners.push({ listener: listener as EventListener, once: false });
    this._events.set(event, listeners);
    return this;
  }

  /**
   * Add a one-time listener for the given event
   */
  once<K extends keyof EventMap>(event: K, listener: (...args: EventMap[K]) => void): this {
    const listeners = this._events.get(event) ?? [];
    listeners.push({ listener: listener as EventListener, once: true });
    this._events.set(event, listeners);
    return this;
  }

  /**
   * Remove a listener for the given event
   */
  off<K extends keyof EventMap>(event: K, listener: (...args: EventMap[K]) => void): this {
    return this.removeListener(event, listener);
  }

  /**
   * Remove a listener for the given event (alias for off)
   */
  removeListener<K extends keyof EventMap>(
    event: K,
    listener: (...args: EventMap[K]) => void,
  ): this {
    const listeners = this._events.get(event);
    if (!listeners) return this;

    const index = listeners.findIndex((entry) => entry.listener === listener);
    if (index !== -1) {
      listeners.splice(index, 1);
      if (listeners.length === 0) {
        this._events.delete(event);
      }
    }
    return this;
  }

  /**
   * Remove all listeners for the given event, or all events if no event specified
   */
  removeAllListeners<K extends keyof EventMap>(event?: K): this {
    if (event !== undefined) {
      this._events.delete(event);
    } else {
      this._events.clear();
    }
    return this;
  }

  /**
   * Emit an event with the given arguments
   */
  emit<K extends keyof EventMap>(event: K, ...args: EventMap[K]): boolean {
    const listeners = this._events.get(event);
    if (!listeners || listeners.length === 0) return false;

    // Copy the array to avoid issues if listeners modify it
    const entries = [...listeners];

    // Remove once listeners before calling
    const remaining = listeners.filter((entry) => !entry.once);
    if (remaining.length === 0) {
      this._events.delete(event);
    } else if (remaining.length !== listeners.length) {
      this._events.set(event, remaining);
    }

    for (const entry of entries) {
      try {
        entry.listener(...args);
      } catch (error) {
        // Emit error event if available and this isn't an error event
        if (event !== 'error' && this._events.has('error' as K)) {
          this.emit('error' as K, ...[error] as EventMap[K]);
        } else {
          throw error;
        }
      }
    }

    return true;
  }

  /**
   * Get the number of listeners for the given event
   */
  listenerCount<K extends keyof EventMap>(event: K): number {
    return this._events.get(event)?.length ?? 0;
  }

  /**
   * Get the listeners for the given event
   */
  listeners<K extends keyof EventMap>(event: K): ((...args: EventMap[K]) => void)[] {
    const entries = this._events.get(event) ?? [];
    return entries.map((entry) => entry.listener as (...args: EventMap[K]) => void);
  }

  /**
   * Get the raw listeners for the given event (includes once wrappers)
   */
  rawListeners<K extends keyof EventMap>(event: K): ((...args: EventMap[K]) => void)[] {
    return this.listeners(event);
  }

  /**
   * Get all event names that have listeners
   */
  eventNames(): (keyof EventMap)[] {
    return [...this._events.keys()];
  }

  /**
   * Prepend a listener to the beginning of the listeners array
   */
  prependListener<K extends keyof EventMap>(
    event: K,
    listener: (...args: EventMap[K]) => void,
  ): this {
    const listeners = this._events.get(event) ?? [];
    listeners.unshift({ listener: listener as EventListener, once: false });
    this._events.set(event, listeners);
    return this;
  }

  /**
   * Prepend a one-time listener to the beginning of the listeners array
   */
  prependOnceListener<K extends keyof EventMap>(
    event: K,
    listener: (...args: EventMap[K]) => void,
  ): this {
    const listeners = this._events.get(event) ?? [];
    listeners.unshift({ listener: listener as EventListener, once: true });
    this._events.set(event, listeners);
    return this;
  }

  /**
   * Get the maximum number of listeners
   */
  getMaxListeners(): number {
    return this._maxListeners;
  }

  /**
   * Set the maximum number of listeners
   */
  setMaxListeners(n: number): this {
    this._maxListeners = n;
    return this;
  }
}

/**
 * Static method to get listener count (for compatibility)
 */
export function listenerCount<EventMap extends Record<string, unknown[]>>(
  emitter: EventEmitter<EventMap>,
  event: keyof EventMap,
): number {
  return emitter.listenerCount(event);
}
