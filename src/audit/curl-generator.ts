import { HttpMethod } from '../types.js';

export interface CurlOptions {
  url: string;
  method: HttpMethod;
  headers?: Record<string, string>;
  data?: unknown;
  rawBody?: string;
}

export function generateCurlCommand(options: CurlOptions): string {
  const parts: string[] = ['curl -s -S -i'];

  if (options.method !== 'GET') {
    parts.push(`-X ${options.method}`);
  }

  if (options.headers) {
    for (const [key, value] of Object.entries(options.headers)) {
      parts.push(`-H "${key}: ${value}"`);
    }
  }

  if (options.rawBody !== undefined) {
    // Escape single quotes for bash
    const escaped = options.rawBody.replace(/'/g, `'\\''`);
    parts.push(`-d '${escaped}'`);
  } else if (options.data !== undefined) {
    const jsonStr = JSON.stringify(options.data).replace(/'/g, `'\\''`);
    parts.push(`-d '${jsonStr}'`);
  }

  parts.push(`"${options.url}"`);

  return parts.join(' ');
}
