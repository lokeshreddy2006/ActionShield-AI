/**
 * ActionShield AI - Centralized API Configuration
 *
 * In local development:
 *   Uses an empty string '' by default so requests use relative paths (e.g. /health, /evaluate),
 *   which are seamlessly proxied to http://127.0.0.1:8000 via vite.config.js.
 *
 * In production:
 *   Uses VITE_API_BASE_URL if set, or defaults to the deployed live FastAPI backend:
 *   https://actionshield-ai.onrender.com
 */

const DEFAULT_PROD_API_BASE_URL = 'https://actionshield-ai.onrender.com'

const rawBaseUrl =
  import.meta.env.VITE_API_BASE_URL !== undefined
    ? import.meta.env.VITE_API_BASE_URL
    : import.meta.env.DEV
      ? ''
      : DEFAULT_PROD_API_BASE_URL

export const API_BASE_URL = (rawBaseUrl || '').replace(/\/+$/, '')

/**
 * Builds a complete endpoint URL using the configured API base URL.
 *
 * @param {string} path - The relative endpoint path (e.g., '/health', '/audit?limit=50')
 * @returns {string} The fully qualified or proxy-relative URL
 */
export function apiUrl(path) {
  if (!path) return API_BASE_URL
  const cleanPath = path.startsWith('/') ? path : `/${path}`
  return `${API_BASE_URL}${cleanPath}`
}
