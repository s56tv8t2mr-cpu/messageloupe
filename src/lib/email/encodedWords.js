export function decodeEncodedWords(value) {
  if (!value) return value;

  return value
    .replace(/(=\?[^?]+\?[qQbB]\?[^?]*\?=)\s+(?==\?[^?]+\?[qQbB]\?[^?]*\?=)/g, '$1')
    .replace(/=\?([^?]+)\?([qQbB])\?([^?]*)\?=/g, (_match, charset, encoding, payload) => {
      try {
        const normalizedCharset = String(charset || '').toLowerCase();
        if (!/^utf-?8$|^us-ascii$|^iso-8859-1$/.test(normalizedCharset)) return payload;

        if (encoding.toLowerCase() === 'q') {
          const decoded = payload
            .replace(/_/g, ' ')
            .replace(/=([0-9A-F]{2})/gi, (_m, hex) => String.fromCharCode(parseInt(hex, 16)));
          return normalizedCharset === 'iso-8859-1'
            ? decoded
            : new TextDecoder().decode(Uint8Array.from(decoded, (char) => char.charCodeAt(0)));
        }

        if (encoding.toLowerCase() === 'b' && typeof atob === 'function') {
          const binary = atob(payload.replace(/\s/g, ''));
          return normalizedCharset === 'iso-8859-1'
            ? binary
            : new TextDecoder().decode(Uint8Array.from(binary, (char) => char.charCodeAt(0)));
        }
      } catch {
        // Return the undecoded payload below.
      }
      return payload;
    });
}
