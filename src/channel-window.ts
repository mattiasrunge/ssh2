/**
 * Coordinates consumers that share a channel's mutable outgoing endpoint.
 *
 * SFTP writes directly through Protocol, rather than through Channel, but it
 * shares Channel.outgoing for SSH flow control. Keep the notification keyed by
 * that shared object so a window adjustment can resume buffered SFTP packets.
 */

type WindowAdjustListener = () => void;

const listeners = new WeakMap<object, Set<WindowAdjustListener>>();

export function onWindowAdjust(
  endpoint: object,
  listener: WindowAdjustListener,
): () => void {
  let endpointListeners = listeners.get(endpoint);
  if (!endpointListeners) {
    endpointListeners = new Set();
    listeners.set(endpoint, endpointListeners);
  }
  endpointListeners.add(listener);

  return () => {
    endpointListeners.delete(listener);
    if (endpointListeners.size === 0) listeners.delete(endpoint);
  };
}

export function notifyWindowAdjust(endpoint: object): void {
  for (const listener of listeners.get(endpoint) ?? []) listener();
}
